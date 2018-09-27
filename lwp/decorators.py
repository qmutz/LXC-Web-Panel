from flask import session, request, render_template
from lwp.database.models import ApiTokens

def if_logged_in(function=render_template, f_args=('login.html', )):
    """
    helper decorator to verify if a user is logged
    """
    def decorator(handler):
        def new_handler(*args, **kwargs):
            if 'logged_in' in session:
                return handler(*args, **kwargs)
            else:
                token = request.headers.get('Private-Token')
                results = ApiTokens.select().where(ApiTokens.token == token).limit(1)
                result = results[0] if len(results) > 0 else None
                if result is not None:
                    return handler(*args, **kwargs)
            return function(*f_args)
        new_handler.__name__ = handler.__name__
        return new_handler
    return decorator
