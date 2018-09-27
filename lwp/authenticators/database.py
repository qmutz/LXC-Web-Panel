# -*- coding: utf-8 -*-
from lwp.utils import hash_passwd
from lwp.database.models import Users


class database:
    def authenticate(self, username, password):
        hash_password = hash_passwd(password)
        results = Users.select().where((Users.username == username)).limit(1)
        return results[0] if len(results) > 0 else None
