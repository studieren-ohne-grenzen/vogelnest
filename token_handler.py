import config
import datetime
import jwt

# Erzeugt ein JWT Token für einen Nutzer
def create_session_jwt_token(username):
    return jwt.encode({
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
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

def create_initial_confirmation_jwt_token(username, email):
    return jwt.encode({
        'type': 'initial_confirmation',
        'username': username,
        'email': email,
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
