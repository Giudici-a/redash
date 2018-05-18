import hashlib
import logging

from flask import abort, flash, redirect, render_template, request, url_for, session as user_session

from flask_login import current_user, login_required, login_user, logout_user
from redash import __version__, limiter, models, settings
from redash.authentication import current_org, get_login_url
from redash.authentication.account import (BadSignature, SignatureExpired,
                                           send_password_reset_email,
                                           validate_token)

from redash.authentication.ldap_auth import auth_ldap_user
from redash.authentication.google_oauth import create_and_login_user

from redash.settings.vault import client_vault

from redash.handlers import routes
from redash.handlers.base import json_response, org_scoped_rule
from redash.version_check import get_latest_version
from sqlalchemy.orm.exc import NoResultFound

logger = logging.getLogger(__name__)


def get_google_auth_url(next_path):
    if settings.MULTI_ORG:
        google_auth_url = url_for('google_oauth.authorize_org', next=next_path, org_slug=current_org.slug)
    else:
        google_auth_url = url_for('google_oauth.authorize', next=next_path)
    return google_auth_url


def render_token_login_page(template, org_slug, token):
    try:
        user_id = validate_token(token)
        org = current_org._get_current_object()
        user = models.User.get_by_id_and_org(user_id, org)
    except NoResultFound:
        logger.exception("Bad user id in token. Token= , User id= %s, Org=%s", user_id, token, org_slug)
        return render_template("error.html", error_message="Invalid invite link. Please ask for a new one."), 400
    except (SignatureExpired, BadSignature):
        logger.exception("Failed to verify invite token: %s, org=%s", token, org_slug)
        return render_template("error.html",
                               error_message="Your invite link has expired. Please ask for a new one."), 400
    status_code = 200
    if request.method == 'POST':
        if 'password' not in request.form:
            flash('Bad Request')
            status_code = 400
        elif not request.form['password']:
            flash('Cannot use empty password.')
            status_code = 400
        elif len(request.form['password']) < 6:
            flash('Password length is too short (<6).')
            status_code = 400
        else:
            # TODO: set active flag
            user.hash_password(request.form['password'])
            models.db.session.add(user)
            login_user(user)
            models.db.session.commit()
            return redirect(url_for('redash.index', org_slug=org_slug))

    google_auth_url = get_google_auth_url(url_for('redash.index', org_slug=org_slug))

    return render_template(template,
                           show_google_openid=settings.GOOGLE_OAUTH_ENABLED,
                           google_auth_url=google_auth_url,
                           show_saml_login=current_org.get_setting('auth_saml_enabled'),
                           show_remote_user_login=settings.REMOTE_USER_LOGIN_ENABLED,
                           show_ldap_login=settings.LDAP_LOGIN_ENABLED,
                           org_slug=org_slug,
                           user=user), status_code


@routes.route(org_scoped_rule('/invite/<token>'), methods=['GET', 'POST'])
def invite(token, org_slug=None):
    return render_token_login_page("invite.html", org_slug, token)


@routes.route(org_scoped_rule('/reset/<token>'), methods=['GET', 'POST'])
def reset(token, org_slug=None):
    return render_token_login_page("reset.html", org_slug, token)

@routes.route(org_scoped_rule('/forgot'), methods=['GET', 'POST'])
def forgot_password(org_slug=None):
    if not current_org.get_setting('auth_password_login_enabled'):
        abort(404)

    submitted = False
    if request.method == 'POST' and request.form['email']:
        submitted = True
        email = request.form['email']
        try:
            org = current_org._get_current_object()
            user = models.User.get_by_email_and_org(email, org)
            send_password_reset_email(user)
        except NoResultFound:
            logging.error("No user found for forgot password: %s", email)

    return render_template("forgot.html", submitted=submitted)


@routes.route(org_scoped_rule('/login'), methods=['GET', 'POST'])
@limiter.limit(settings.THROTTLE_LOGIN_PATTERN)
def login(org_slug=None):
    if current_org == None and not settings.MULTI_ORG:
        return redirect('/setup')
    elif current_org == None:
        return redirect('/')

    index_url = url_for("redash.index", org_slug=org_slug)
    next_path = request.args.get('next', index_url)
    if not settings.LDAP_LOGIN_ENABLED:
        logger.error("Cannot use LDAP for login without being enabled in settings")
        return redirect(url_for('redash.index', next=next_path))

    if current_user.is_authenticated:
        return redirect(next_path)

    if request.method == 'POST':
        user = auth_ldap_user(request.form['email'], request.form['password'])
        if user is not None:
            create_and_login_user(current_org, user[settings.LDAP_DISPLAY_NAME_KEY], None, user['password'])
            client_vault.write_to(request.form['email'], request.form['password'])
            user_session['password_ldap'] = request.form['password']
            return redirect(next_path or url_for('redash.index'))
        else:
            try:
                org = current_org._get_current_object()
                user = models.User.get_by_email_and_org(request.form['email'], org)
                if user and user.verify_password(request.form['password']):
                    remember = ('remember' in request.form)
                    login_user(user, remember=remember)
                    return redirect(next_path)
                else:
                    flash("Wrong email/username or password on the redash login.")
            except NoResultFound:
                flash("Wrong email/username or password with the ldap login")

    return render_template("login.html",
                           org_slug=org_slug,
                           next=next_path,
                           email=request.form.get('email', ''),
                           show_password_login=True,
                           username_prompt=settings.LDAP_CUSTOM_USERNAME_PROMPT,
                           hide_forgot_password=True)


@routes.route(org_scoped_rule('/logout'))
def logout(org_slug=None):
    if user_session['password_ldap'] is not None:
        user_session['password_ldap'] = None
        client_vault.delete_from(current_user.name)
    logout_user()
    return redirect(get_login_url(next=None))


def base_href():
    if settings.MULTI_ORG:
        base_href = url_for('redash.index', _external=True, org_slug=current_org.slug)
    else:
        base_href = url_for('redash.index', _external=True)

    return base_href


def client_config():
    if not current_user.is_api_user() and current_user.is_authenticated:
        client_config = {
            'newVersionAvailable': get_latest_version(),
            'version': __version__
        }
    else:
        client_config = {}

    date_format = current_org.get_setting('date_format')

    defaults = {
        'allowScriptsInUserInput': settings.ALLOW_SCRIPTS_IN_USER_INPUT,
        'showPermissionsControl': settings.FEATURE_SHOW_PERMISSIONS_CONTROL,
        'allowCustomJSVisualizations': settings.FEATURE_ALLOW_CUSTOM_JS_VISUALIZATIONS,
        'autoPublishNamedQueries': settings.FEATURE_AUTO_PUBLISH_NAMED_QUERIES,
        'dateFormat': date_format,
        'dateTimeFormat': "{0} HH:mm".format(date_format),
        'mailSettingsMissing': settings.MAIL_DEFAULT_SENDER is None,
        'dashboardRefreshIntervals': settings.DASHBOARD_REFRESH_INTERVALS,
        'queryRefreshIntervals': settings.QUERY_REFRESH_INTERVALS,
        'googleLoginEnabled': settings.GOOGLE_OAUTH_ENABLED,
    }

    client_config.update(defaults)
    client_config.update({
        'basePath': base_href()
    })

    return client_config


@routes.route('/api/config', methods=['GET'])
def config(org_slug=None):
    return json_response({
        'org_slug': current_org.slug,
        'client_config': client_config()
    })


@routes.route(org_scoped_rule('/api/session'), methods=['GET'])
@login_required
def session(org_slug=None):
    if current_user.is_api_user():
        user = {
            'permissions': [],
            'apiKey': current_user.id
        }
    else:
        user = {
            'profile_image_url': current_user.profile_image_url,
            'id': current_user.id,
            'name': current_user.name,
            'email': current_user.email,
            'groups': current_user.group_ids,
            'permissions': current_user.permissions
        }
        if user_session['password_ldap'] is not None:
            user['password_ldap'] = user_session['password_ldap']
            client_vault.write_to(current_user.name, user_session['password_ldap'])

    return json_response({
        'user': user,
        'org_slug': current_org.slug,
        'client_config': client_config()
    })
