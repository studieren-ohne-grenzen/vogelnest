from flask import Flask, request, url_for, session, abort, jsonify
from datetime import timedelta
from flask import render_template, redirect
from api import LdapApi
from authlib.integrations.flask_client import OAuth

import json
import ldap_json
import config

app = Flask(__name__)
app.secret_key = config.SESSIONS_ENC_KEY
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

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
    print(token)
    
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
    if not session.get('logged_in'):
        return abort(401)
    return 'Hello, World!'

@app.route('/users', methods=['GET'])
def users():
    if not session.get('logged_in'):
        return abort(401)
    return 'Hello, World!'

@app.route('/users/<uid>', methods=['GET'])
def user(uid):
    if not session.get('logged_in'):
        return abort(401)
    ldap_user = api.get_user(uid)
    return str(ldap_user)

@app.route('/users/<uid>/set_password', methods=['POST'])
def user_set_password(uid):
    if not session.get('logged_in'):
        return abort(401)
    uid = session['username']
    old_password = request.json.get('old_password')
    new_password = request.json.get('new_password')
    if api.check_user_password(uid, old_password):
        api.set_user_password(uid, new_password)
        return "ok", 200
    else:
        return "invalid old password", 401

@app.route('/users/<uid>/reset_password', methods=['POST'])
def user_reset_password(uid):
    if not session.get('logged_in'):
        return abort(401)
    return 'Hello, World!'

@app.route('/users/<uid>/activate', methods=['POST'])
def user_activate(uid):
    if not session.get('logged_in'):
        return abort(401)
    api.activate_user(uid)
    return "ok", 200

@app.route('/users/<uid>/owned_groups', methods=['GET'])
def user_owned_groups(uid):
    if not session.get('logged_in'):
        return abort(401)
    return 'Hello, World!'

@app.route('/groups', methods=['GET'])
def groups():
    if not session.get('logged_in'):
        return abort(401)
    groups = [ldap_json.group_to_dict(x) for x in api.get_groups()]

    return jsonify(groups)

@app.route('/mygroups', methods=['GET'])
def mygroups():
    if not session.get('logged_in'):
        return abort(401)
    username = session.get('username')
    pending_groups = [ldap_json.group_to_dict(x) for x in api.get_groups_as_pending_member(username)]
    member_groups = [ldap_json.group_to_dict(x) for x in api.get_groups_as_member(username)]
    owned_groups = [ldap_json.group_to_dict(x) for x in api.get_groups_as_owner(username)]

    # Groups can overlap. If you're owner you're always also member.
    # But the interesting information is that you're owner.
    member_groups = list(filter(lambda x: x not in owned_groups, member_groups))

    # Add information about membership
    for group in pending_groups:
        group['membership'] = 'pending'
    for group in member_groups:
        group['membership'] = 'member'
    for group in owned_groups:
        group['membership'] = 'admin'

    all_groups = []
    all_groups.extend(pending_groups)
    all_groups.extend(member_groups)
    all_groups.extend(owned_groups)

    return jsonify(all_groups)

@app.route('/groups/<group>/members', methods=['GET'])
def group_members(group):
    if not session.get('logged_in'):
        return abort(401)
    if not any(x.uid == session['username'] for x in api.get_group_owners(group)):
        return abort(401)
    ldap_members = api.get_group_members(group)
    members = []
    for x in ldap_members:
        try:
            members.append(ldap_json.user_to_dict(x))
        except Exception as e:
            print(e)
    return jsonify(members)

@app.route('/groups/<group>/pending_members', methods=['GET','POST'])
def group_pending_members(group):
    if not session.get('logged_in'):
        return abort(401)
    if not any(x.uid == session['username'] for x in api.get_group_owners(group)):
        return abort(401)
    ldap_members = api.get_group_pending_members(group)
    members = []
    for x in ldap_members:
        try:
            members.append(ldap_json.user_to_dict(x))
        except Exception as e:
            print(e)
    return jsonify(members)

@app.route('/groups/<group>/owners', methods=['GET'])
def group_owners(group):
    if not session.get('logged_in'):
        return abort(401)
    ldap_owners = api.get_group_owners(group)
    owners = []
    for x in ldap_owners:
        try:
            owners.append(ldap_json.user_to_dict(x))
        except Exception as e:
            print(e)
    return jsonify(owners)

@app.route('/groups/<group>/add_member/<uid>', methods=['POST'])
def add_user_to_group(group, uid):
    if not session.get('logged_in'):
        return abort(401)
    if not any(x.uid == session['username'] for x in api.get_group_owners(group)):
        return abort(401)
    api.add_group_member(group, uid)

@app.route('/groups/<group>/remove_member/<uid>', methods=['POST'])
def remove_user_from_group(group, uid):
    if not session.get('logged_in'):
        return abort(401)
    if not any(x.uid == session['username'] for x in api.get_group_owners(group)):
        return abort(401)
    api.remove_group_member(group, uid)

@app.route('/groups/<group>/add_owner/<uid>', methods=['POST'])
def add_owner_to_group(group, uid):
    if not session.get('logged_in'):
        return abort(401)
    if not any(x.uid == session['username'] for x in api.get_group_owners(group)):
        return abort(401)
    api.add_group_owner(group, uid)

@app.route('/groups/<group>/add_owner/<uid>', methods=['POST'])
def remove_owner_from_group(group, uid):
    if not session.get('logged_in'):
        return abort(401)
    if not any(x.uid == session['username'] for x in api.get_group_owners(group)):
        return abort(401)
    api.remove_group_owner(group, uid)

@app.route('/groups/<group>/add_guest/<name>/<mail>', methods=['POST'])
def add_guest_to_group(group, name, mail):
    if not session.get('logged_in'):
        return abort(401)
    if not any(x.uid == session['username'] for x in api.get_group_owners(group)):
        return abort(401)
    uid = api.create_guest(name, mail)
    api.add_group_member(group, uid)

@app.route('/groups/<group>/request_access/', methods=['POST'])
def request_access_to_group(group, uid):
    if not session.get('logged_in'):
        return abort(401)
    if not any(x.uid == session['username'] for x in api.get_group_owners(group)):
        return abort(401)
    api.add_group_member(group, uid)
