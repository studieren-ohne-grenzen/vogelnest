from flask import Flask, request, url_for, abort, jsonify
from datetime import timedelta
from flask import render_template, redirect
from ldap_api import LdapApi, LdapApiException
from ldap3.utils import conv
from middleware import middleware
import token_handler
from os.path import join

import json
import config

import mail

api = LdapApi(config)
app = Flask(__name__)
app.wsgi_app = middleware(app.wsgi_app)

def dn_to_uid(dn):
    return dn.split(',')[0][4:]

def sanitize(x):
    return conv.escape_filter_chars(x, encoding="utf-8")

# converts ldap-style objects to python dicts (yes, there is no better way)
def object_to_dict(obj):
    dictionary = json.loads(obj.entry_to_json())["attributes"]
    keys = dictionary.keys()
    new_dictionary = {}
    for key in list(keys):
        if len(dictionary[key]) >= 1:
            new_dictionary[key.replace("-", "_")] = dictionary[key][0]
        else:
            new_dictionary[key] = None
    return new_dictionary

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
        token = token_handler.create_session_jwt_token(username)
        return token
    else:
        abort(403)

# Checkt, ob ein Token gültig ist
# TODO nur für Debug
# Man tut den Namen als username param und das JWT in das Bearer Feld
# Man bekommt dann seinen Namen geochot
@app.route('/whoami', methods=['GET'])
def whoami():
    uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if uid == None:
        return abort(401)
    info = api.get_user_info(uid)
    return object_to_dict(info)

@app.route('/users', methods=['GET'])
def users(group_id = None):
    if group_id == None:
        pass
    return 'Hello, World!'

@app.route('/users/set_password', methods=['POST'])
def user_set_password():
    uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if uid == None:
        return abort(401)
    old_password = request.json.get('old_password')
    new_password = request.json.get('new_password')
    if api.check_user_password(uid, old_password):
        api.set_user_password(uid, new_password)
        return "ok", 200
    else:
        return "invalid old password", 401

@app.route('/users/set_alternative_mail', methods=['POST'])
def user_set_alternative_mail():
    uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if uid == None:
        return abort(401)
    new_mail = request.json.get('alternative_mail')
    api.set_user_alternative_mail(uid, new_mail)
    return "ok", 200

@app.route('/users/reset_password', methods=['POST'])
def user_reset_password():
    alternative_mail = request.json.get('alternative_mail')
    try:
        user = api.get_user_by_alternative_mail(alternative_mail)
        password_reset_token = token_handler.create_password_reset_jwt_token(user.uid[0]).decode("utf-8")
        mail.send_text_message(alternative_mail, "Passwort-Reset", "emails/password_reset_email.html", {
            "name": user.uid[0],
            "link": join(config.DASHBOARD_URL, "confirm?key=" + password_reset_token),
        })
        return "ok"
    except LdapApiException as e:
        print(e)
        return abort(401)

@app.route('/users/confirm_email', methods=['POST'])
def confirm_email():
    alternative_mail = request.json.get('alternative_mail')
    uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if uid == None:
        return abort(401)
    try:
        email_reset_token = token_handler.create_email_confirmation_jwt_token(uid, alternative_mail).decode("utf-8")
        mail.send_text_message(alternative_mail, "Email-Confirmation", "emails/email_confirmation.html", {
            "name": uid,
            "link": join(config.DASHBOARD_URL, "confirm?key=" + email_reset_token),
        })
        return "ok"
    except LdapApiException as e:
        print(e)
        return abort(401)

@app.route('/users/activate', methods=['POST'])
def user_activate():
    uid = sanitize(request.args.get('uid'))
    api.activate_user(uid)
    return "ok", 200

@app.route('/groups', methods=['GET'])
def groups():
    groups = [object_to_dict(x) for x in api.get_groups()]

    return jsonify(groups)

@app.route('/mygroups', methods=['GET'])
def mygroups():
    username = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if username == None:
        return abort(401)
    pending_groups = [object_to_dict(x) for x in api.get_groups_as_pending_member(username)]
    member_groups = [object_to_dict(x) for x in api.get_groups_as_member(username)]
    owned_groups = [object_to_dict(x) for x in api.get_groups_as_owner(username)]

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
    group_id = sanitize(request.args.get('group_id'))
    uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if uid == None:
        return abort(401)
    if not any(x.uid == uid for x in api.get_group_owners(group_id)):
        return abort(401)
    ldap_members = api.get_group_members(group_id)
    members = []
    for x in ldap_members:
        try:
            members.append(object_to_dict(x))
        except Exception as e:
            print(e)
    return jsonify(members)

@app.route('/groups/guests', methods=['GET'])
def group_guests():
    group_id = sanitize(request.args.get('group_id'))
    uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if uid == None:
        return abort(401)
    if not any(x.uid == uid for x in api.get_group_owners(group_id)):
        return abort(401)
    ldap_members = api.get_group_guests(group_id)
    members = []
    for x in ldap_members:
        try:
            members.append(object_to_dict(x))
        except Exception as e:
            print(e)
    return jsonify(members)

@app.route('/groups/pending_members', methods=['GET'])
def group_pending_members():
    group_id = sanitize(request.args.get('group_id'))
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    ldap_members = api.get_group_pending_members(group_id)
    members = []
    for x in ldap_members:
        try:
            members.append(object_to_dict(x))
        except Exception as e:
            print(e)
    return jsonify(members)

@app.route('/groups/owners', methods=['GET'])
def group_owners():
    group_id = sanitize(request.args.get('group_id'))
    ldap_owners = api.get_group_owners(group_id)
    owners = []
    for x in ldap_owners:
        try:
            owners.append(object_to_dict(x))
        except Exception as e:
            print(e)
    return jsonify(owners)

@app.route('/groups/add_member', methods=['POST'])
def add_user_to_group():
    group_id = sanitize(request.args.get('group_id'))
    uid = sanitize(request.args.get('uid'))
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    api.add_group_member(group_id, uid)
    return "ok"

@app.route('/groups/remove_member', methods=['POST'])
def remove_user_from_group():
    group_id = sanitize(request.args.get('group_id'))
    uid = sanitize(request.args.get('uid'))
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    api.remove_group_member(group_id, uid)
    return "ok"

@app.route('/groups/add_owner', methods=['POST'])
def add_owner_to_group():
    group_id = sanitize(request.args.get('group_id'))
    uid = sanitize(request.args.get('uid'))
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    api.add_group_owner(group_id, uid)
    return "ok"

@app.route('/groups/add_owner', methods=['POST'])
def remove_owner_from_group():
    group_id = sanitize(request.args.get('group_id'))
    uid = sanitize(request.args.get('uid'))
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    api.remove_group_owner(group_id, uid)
    return "ok"

@app.route('/groups/add_guest', methods=['GET'])
def add_guest_to_group():
    group_id = sanitize(request.args.get('group_id'))
    name = sanitize(request.args.get('name'))
    mail = sanitize(request.args.get('mail'))
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    uid = api.create_guest(name, mail)
    api.add_group_member(group_id, uid)
    return uid

@app.route('/groups/request_access', methods=['POST'])
def request_access_to_group():
    group_id = sanitize(request.args.get('group_id'))
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    api.add_group_member(group_id, my_uid)
    return "ok"

@app.route('/groups/accept_pending_member', methods=['POST'])
def accept_pending_member():
    group_id = sanitize(request.args.get('group_id'))
    uid = sanitize(request.args.get('uid'))
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    api.remove_group_pending_member(group_id, uid)
    api.add_group_member(group_id, uid)
    return "ok"

@app.route('/confirm', methods=['GET'])
def confirm_mail():
    token_str = request.args.get('key')
    token_str, token_type = token_handler.read_email_token(token_str)
    redirect_url = None
    if token_type == None:
        return abort(401)
    elif token_type == "password_reset":
        redirect_url = config.FRONTEND_URL + "/confirm/password"
    elif token_type == "email_confirmation":
        redirect_url = config.FRONTEND_URL + "/confirm/email"
    return redirect_url(redirect_url, code=302)
