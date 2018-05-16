import os

import hvac
from redash import settings

class Vault:
    vault = None

    def __init__(self):
        self.vault = hvac.Client(url=settings.VAULT_URL, token=settings.VAULT_TOKEN)
        self.vault.token = settings.VAULT_TOKEN
        print self.vault.is_authenticated()

    def write_to(self, key, value):
        print settings.VAULT_SECRET + key
        self.vault.write(settings.VAULT_SECRET + key, password_ldap=value, lease='1h')

    def read_to(self, key):
        return self.vault.read(settings.VAULT_SECRET + key)

    def delete_from(self, key):
        self.vault.delete(settings.VAULT_SECRET + key)


client_vault = Vault()
