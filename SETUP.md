# Adotmob Redash

## Requirements and install

The adotmob redash requires to follow this documentation:

* https://redash.io/help/open-source/dev-guide/setup

You also need the vault installation:

* https://www.vaultproject.io/docs/install/index.html

## Usage

We took the redash and we fork it. The goal was to use ldap credentials for the presto's requests.

### Permissions

If you cannot connect to redash it's because you sould not have a ldap account. 

### Initialization

* Web server: ```bash bin/run ./manage.py runserver --debugger --reload```
* Celery: ```bash ./bin/run celery worker --app=redash.worker --beat -Qscheduled_queries,queries,celery -c2```
* Webpack dev server: ```bash npm run start```
* Postgresql: ```bash pg_ctl -D /usr/local/var/postgres -l logfile start```
* vault: ```bash vault server -config=config.hcl```

### Running Test

* Currently we currently have tests only for the backend code. To run them invoke:
```bash pytest tests/```

## Fork of

* https://github.com/getredash/redash