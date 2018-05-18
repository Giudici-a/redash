import os

import hvac
from redash import settings


class Vault:
    vault = None

    def __init__(self):
        self.vault = hvac.Client(url=settings.VAULT_URL)
        app_role_res = self.app_role(settings.VAULT_APPROLE_ROLE_ID, settings.VAULT_APPROLE_SECRET_ID)
        self.vault.token = app_role_res['auth']['client_token']

    def app_role(self, role_id, secret_id):
        ret = self.vault.auth_approle(role_id, secret_id)
        return ret

    def set_token(self, token):
        self.vault.token = token

    def write_to(self, key, value):
        self.vault.write(settings.VAULT_SECRET + key, password_ldap=value, lease='1h')

    def read_to(self, key):
        ret = self.vault.read(settings.VAULT_SECRET + key)
        return ret

    def delete_from(self, key):
        self.vault.delete(settings.VAULT_SECRET + key)


client_vault = Vault()
