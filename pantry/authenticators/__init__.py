# -*- coding: utf-8 -*-


def get_authenticator(auth):
    if auth:
        n = "{}.{}".format(__name__, auth)
        module = __import__(n, fromlist=[__name__])
        class_ = getattr(module, auth)
        return class_()
    return None
