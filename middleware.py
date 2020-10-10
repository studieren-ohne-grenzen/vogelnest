from werkzeug.wrappers import Request, Response
from werkzeug.datastructures import MultiDict
from ldap3.utils import conv
import io
import token_handler

# Middleware for sanitizing every input

class middleware():
    def __init__(self, app):
        self.app = app
    def __call__(self, environ, start_response):
        request = Request(environ)
        authheader = request.headers.get('Authorization')

        uid = token_handler.get_jwt_user(authheader)
        print(request.url.replace(request.url_root, ""))
        if uid == None and \
                not request.url.replace(request.url_root, "") in ["login", "users/reset_password", "users/set_password_with_key"] and \
                not request.url.replace(request.url_root, "").startswith("confirm"): 
            res = Response(u'Authorization failed', mimetype= 'text/plain', status=401)
            return res(environ, start_response)

        return self.app(environ, start_response)
