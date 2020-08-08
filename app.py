from flask import Flask, request, url_for, session, abort
from flask import render_template, redirect
from api import LdapApi
from authlib.integrations.flask_client import OAuth

import config

app = Flask(__name__)
app.secret_key = config.SESSIONS_ENC_KEY

api = LdapApi(config)
oauth = OAuth(app)

oauth.register(
    name='sog',
    client_id= config.OAUTH_CLIENT_ID,
    client_secret= config.OAUTH_CLIENT_SECRET,
    access_token_url=config.OAUTH_TOKEN_URL,
    access_token_params=None,
    authorize_url=config.OAUTH_AUTH_URL,
    authorize_params=None,
    api_base_url=config.OAUTH_API_URL,
    client_kwargs = {
        'scope' : 'profile',
        'token_endpoint_auth_method': 'client_secret_basic',
    }
)


@app.route('/')
def homepage():
    return abort(403)

@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return oauth.sog.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    token = oauth.sog.authorize_access_token()
    
    userdata = oauth.sog.get('user').json()
    username = userdata['username']
    
    # Wir bereinigen den Username um den SOG-Prefix
    if username.startswith('sog_'):
        username = username[4:]

    # Wir speichern den Username in der Session
    session['logged_in'] = True
    session['username'] = username

    return redirect(config.DASHBOARD_URL)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect('/login')

@app.route('/whoami', methods=['GET'])
def whoami():
    if session.get('logged_in') == True:
        return session.get('username')
    return abort(401)

@app.route('/guests', methods=['POST'])
def guests():
    return 'Hello, World!'

@app.route('/users', methods=['GET', 'POST'])
def users():
    return 'Hello, World!'

@app.route('/users/<uid>', methods=['GET', 'DELETE'])
def user(uid):
    ldap_user = api.get_user(uid)
    return str(ldap_user)

@app.route('/users/<uid>/set_password', methods=['POST'])
def user_set_password(uid):
    return 'Hello, World!'

@app.route('/users/<uid>/reset_password', methods=['POST'])
def user_reset_password(uid):
    return 'Hello, World!'

@app.route('/users/<uid>/activate', methods=['POST'])
def user_activate(uid):
    return 'Hello, World!'

@app.route('/users/<uid>/groups', methods=['GET'])
def user_groups(uid):
    return 'Hello, World!'

@app.route('/users/<uid>/owned_groups', methods=['GET'])
def user_owned_groups(uid):
    return 'Hello, World!'

@app.route('/groups', methods=['GET', 'POST'])
def groups():
    return 'Hello, World!'

@app.route('/groups/<group>', methods=['GET'])
def group(group):
    return 'Hello, World!'

@app.route('/groups/<group>/members', methods=['GET', 'POST'])
def group_members(group):
    return 'Hello, World!'

@app.route('/groups/<group>/members/<uid>', methods=['DELETE'])
def group_member(group, uid):
    return 'Hello, World!'

@app.route('/groups/<group>/pending_members', methods=['GET','POST'])
def group_pending_members(group):
    return 'Hello, World!'

@app.route('/groups/<group>/pending_members/<uid>', methods=['DELETE'])
def group_pending_member(group, uid):
    return 'Hello, World!'

@app.route('/groups/<group>/owners', methods=['GET', 'POST'])
def group_owners(group):
    return 'Hello, World!'

@app.route('/groups/<group>/owners/<uid>', methods=['DELETE'])
def group_owner(group, uid):
    return 'Hello, World!'
