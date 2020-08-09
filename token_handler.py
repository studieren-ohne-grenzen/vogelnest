import config
import datetime
import jwt
import app

# Erzeugt ein JWT Token für einen Nutzer
def create_session_jwt_token(uid):
    return jwt.encode({
        'username': uid,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=16)
    }, config.JWT_SECRET, algorithm='HS256')

def create_email_confirmation_jwt_token(uid, email):
    return jwt.encode({
        'type': 'email_confirmation',
        'uid': uid,
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=16)
    }, config.JWT_SECRET, algorithm='HS256')

def create_password_reset_jwt_token(uid):
    return jwt.encode({
        'type': 'password_reset',
        'uid': uid,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=16)
    }, config.JWT_SECRET, algorithm='HS256')

# checks header and returns username if header is valid
# returns None if header is invalid
def get_jwt_user(header):
    if header == None:
        return None
    header_fields = header.split(" ")
    if header_fields[0] != "Bearer":
        return None
    try:
        jwt_user = jwt.decode(header_fields[1], config.JWT_SECRET, algorithms=['HS256']).get("username")
    except jwt.InvalidTokenError:
        return None
    return jwt_user

def read_email_token(token_str):
    try:
        token = jwt.decode(token_str, config.JWT_SECRET, algorithms=['HS256'])
        print("yooo token", token)
        if token["type"] == "password_reset":
            # redirect to password reset page with token
            return "password reset " + token_str
        elif token["type"] == "email_confirmation":
            print(token)
            app.api.set_user_mail(app.sanitize(token["uid"]), app.sanitize(token["email"]))
            return "ok"
        else:
            return None
    except jwt.InvalidTokenError:
        return None
