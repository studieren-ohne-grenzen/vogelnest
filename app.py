from flask import Flask, request, url_for, abort, jsonify
from datetime import timedelta
from flask import render_template, redirect
from api import LdapApi
from ldap3.utils import conv
from middleware import middleware

import json
import ldap_json
import config

api = LdapApi(config)
app = Flask(__name__)
app.wsgi_app = middleware(app.wsgi_app, api)

@app.route('/')
def homepage():
    return abort(401) # Security by obscurity

# LOGIN
# HTTP 401: Bitte einloggen
# HTTP 403: Falsches Passwort / falscher Nutzername
# Der Client sendet per POST ein JSON Dokument
# Mit Username und Passowrt
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if api.check_user_password(username,password):
        ## Jetzt erzeugen wir das JWT, welches den USER ausweist
        token = api.create_jwt_token(username)
        return token
    else:
        abort(403)

# Checkt, ob ein Token gültig ist
# TODO nur für Debug
# Man tut den Namen als username param und das JWT in das Bearer Feld
# Man bekommt dann seinen Namen geochot
@app.route('/whoami', methods=['GET'])
def whoami():
    uid = api.get_jwt_user(request.headers.get('Authorization'))
    if uid == None:
        return abort(403)
    return uid

@app.route('/users', methods=['GET'])
def users(group_id = None):
    if group_id == None:
        pass
    return 'Hello, World!'

@app.route('/users/set_password', methods=['POST'])
def user_set_password():
    uid = api.get_jwt_user(request.headers.get('Authorization'))
    old_password = request.json.get('old_password')
    new_password = request.json.get('new_password')
    if api.check_user_password(uid, old_password):
        api.set_user_password(uid, new_password)
        return "ok", 200
    else:
        return "invalid old password", 401

@app.route('/users/reset_password', methods=['POST'])
def user_reset_password():
    return 'Hello, World!'

@app.route('/users/activate', methods=['POST'])
def user_activate():
    uid = request.args.get('uid')
    api.activate_user(uid)
    return "ok", 200

@app.route('/groups/', methods=['GET'])
def groups():
    groups = [ldap_json.group_to_dict(x) for x in api.get_groups()]

    return jsonify(groups)

@app.route('/mygroups', methods=['GET'])
def mygroups():
    username = api.get_jwt_user(request.headers.get('Authorization'))
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

@app.route('/groups/members', methods=['GET'])
def group_members():
    group_id = request.args.get('group_id')
    print(group_id)
    uid = api.get_jwt_user(request.headers.get('Authorization'))
    if not any(x.uid == uid for x in api.get_group_owners(group_id)):
        return abort(401)
    ldap_members = api.get_group_members(group_id)
    members = []
    for x in ldap_members:
        try:
            members.append(ldap_json.user_to_dict(x))
        except Exception as e:
            print(e)
    return jsonify(members)

@app.route('/groups/pending_members', methods=['GET'])
def group_pending_members():
    group_id = request.args.get('group_id')
    my_uid = api.get_jwt_user(request.headers.get('Authorization'))
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    ldap_members = api.get_group_pending_members(group_id)
    members = []
    for x in ldap_members:
        try:
            members.append(ldap_json.user_to_dict(x))
        except Exception as e:
            print(e)
    return jsonify(members)

@app.route('/groups/owners', methods=['GET'])
def group_owners():
    group_id = request.args.get('group_id')
    ldap_owners = api.get_group_owners(group_id)
    owners = []
    for x in ldap_owners:
        try:
            owners.append(ldap_json.user_to_dict(x))
        except Exception as e:
            print(e)
    return jsonify(owners)

@app.route('/groups/add_member/', methods=['POST'])
def add_user_to_group():
    group_id = request.args.get('group_id')
    uid = request.args.get('uid')
    my_uid = api.get_jwt_user(request.headers.get('Authorization'))
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    api.add_group_member(group_id, uid)

@app.route('/groups/remove_member/', methods=['POST'])
def remove_user_from_group():
    group_id = request.args.get('group_id')
    uid = request.args.get('uid')
    my_uid = api.get_jwt_user(request.headers.get('Authorization'))
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    api.remove_group_member(group_id, uid)

@app.route('/groups/add_owner/', methods=['POST'])
def add_owner_to_group():
    group_id = request.args.get('group_id')
    uid = request.args.get('uid')
    my_uid = api.get_jwt_user(request.headers.get('Authorization'))
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    api.add_group_owner(group_id, uid)

@app.route('/groups/add_owner/', methods=['POST'])
def remove_owner_from_group():
    group_id = request.args.get('group_id')
    uid = request.args.get('uid')
    my_uid = api.get_jwt_user(request.headers.get('Authorization'))
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    api.remove_group_owner(group_id, uid)

@app.route('/groups/add_guest/', methods=['POST'])
def add_guest_to_group():
    group_id = request.args.get('group_id')
    name = request.args.get('name')
    mail = request.args.get('mail')
    my_uid = api.get_jwt_user(request.headers.get('Authorization'))
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    uid = api.create_guest(name, mail)
    api.add_group_member(group_id, uid)

@app.route('/groups/request_access/', methods=['POST'])
def request_access_to_group():
    group_id = request.args.get('group_id')
    my_uid = api.get_jwt_user(request.headers.get('Authorization'))
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    api.add_group_member(group_id, my_uid)
