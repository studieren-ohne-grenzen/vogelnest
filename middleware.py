from werkzeug.wrappers import Request, Response
from werkzeug.datastructures import MultiDict
from ldap3.utils import conv
import io

# Middleware for sanitizing every input

class middleware():
    def __init__(self, app, api):
        self.app = app
        self.api = api
    def __call__(self, environ, start_response):
        request = Request(environ)
        authheader = request.headers.get('Authorization')

        uid = self.api.get_jwt_user(authheader)
        if uid == None and not request.url.replace(request.url_root, "") == "login":
            res = Response(u'Authorization failed', mimetype= 'text/plain', status=401)
            return res(environ, start_response)

        return self.app(environ, start_response)
