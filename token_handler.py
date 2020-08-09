import config
import datetime
import jwt
import app

# Erzeugt ein JWT Token für einen Nutzer
def create_session_jwt_token(username):
    return jwt.encode({
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=16)
    }, config.JWT_SECRET, algorithm='HS256')

def create_email_confirmation_jwt_token(username, email):
    return jwt.encode({
        'type': 'email_confirmation',
        'username': username,
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=48)
    }, config.JWT_SECRET, algorithm='HS256')

def create_password_reset_jwt_token(username):
    return jwt.encode({
        'type': 'password_reset',
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }, config.JWT_SECRET, algorithm='HS256')

# checks header and returns username if header is valid
# returns None if header is invalid
def get_jwt_user(header):
    if header == None:
        return None
    header_fields = header.split(" ")
    if header_fields[0] != "Bearer":
        return None
    return get_token_user_with_string(header_fields[1])

def get_token_user_with_string(token_str):
    try:
        jwt_user = jwt.decode(token_str, config.JWT_SECRET, algorithms=['HS256']).get("username")
    except jwt.InvalidTokenError:
        return None
    return jwt_user


def read_email_token(token_str):
    try:
        token = jwt.decode(token_str, config.JWT_SECRET, algorithms=['HS256'])
        if token["type"] == "password_reset":
            pass
        elif token["type"] == "email_confirmation":
            app.api.set_user_mail(app.sanitize(token["username"]), app.sanitize(token["email"]))
        else:
            return None
        return token["type"]
    except jwt.InvalidTokenError:
        return None
