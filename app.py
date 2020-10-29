from flask import Flask, request, url_for, abort, jsonify
from datetime import timedelta
from flask import render_template, redirect
from ldap_api import LdapApi, LdapApiException
from ldap3.utils import conv
from middleware import middleware
import token_handler
import group_request_handler
from os.path import join
from urllib.parse import unquote
import jwt

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

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    try:
        successful, _ = api.check_user_password(username, password)
        if successful:
            token = token_handler.create_session_jwt_token(username)
            return token
        else:
            abort(401), "Invalid credentials"
    except Exception as e:
        abort(403)

@app.route('/create_user', methods=['POST'])
def create_user():
    # Handle Auth
    if request.authorization["username"] != "civicrm" or request.authorization["password"] != config.CIVICRM_SECRET:
        abort(403), "Invalid credentials"
    firstName = sanitize(request.json.get('firstName'))
    lastName = sanitize(request.json.get('lastName'))
    email = sanitize(request.json.get('email'))
    lokalgruppe = sanitize(request.json.get('lokalgruppe')) #like lg_aachen

    # Abort 500 if lokalgruppe does not exist
    try:
        api.get_group(lokalgruppe)
    except:
        abort(500, "lokalgruppe " + lokalgruppe " does not exist")

    try:
        username = api.create_member(firstName, lastName,email)

        # Ask member to set password
        password_reset_token = token_handler.create_initial_confirmation_jwt_token(username, email).decode("utf-8")
        mail.send_email(email, "Willkommen bei SOG!", "emails/new_user_onboarding", {
            "firstName" : firstName,
            "name": username,
            "link": join(config.FRONTEND_URL, "confirm?key=" + password_reset_token),
        })

        # request membership in LG. Is non existent LG be dealt with correctly? 
        group_request_handler.request_inactive_pending(api, lokalgruppe, username)
        # Person becomes member of allgemein upon activation

        return username
    except Exception as e:
        print(e)
        abort(500)
    
@app.route('/inactive_info', methods=['GET'])
def inactive_info():
    uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if uid == None:
        return abort(401)
    inactive_user = None
    try:
        inactive_info = api.get_inactive_user(uid)
    except LdapApiException as e:
        return jsonify({
            "inactive": False
        })
    # Get the owners of the group you are pending in
    groups = api.get_groups_as_inactive_pending_member(uid)
    if len(groups) != 1:
        return jsonify({
            "inactive": True
        })
    group = groups[0]
    group_name = str(group.cn)
    pending_group_owners = [object_to_dict(api.get_user(dn_to_uid(str(x)))) for x in group.owner]
    return jsonify({
        "inactive": True,
        "pending_group_name": group_name,
        "pending_group_owners": pending_group_owners,
    })


@app.route('/whoami', methods=['GET'])
def whoami():
    uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if uid == None:
        return abort(401)
    info = api.get_user_info(uid)
    return object_to_dict(info)

@app.route('/users', methods=['GET'])
def users():
    """ Lists all users. Returns their uids in a json array.
        
    To access this, one must be owner in some group.
    """
    # Check if user is admin in some group
    uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if uid == None:
        return abort(401)
    if not api.is_active(uid):
        return abort(401)
    if not api.is_group_owner_anywhere(uid):
        return abort(403), "To access this endpoint, you have to be owner of a group"

    # Ok, they are. List all users and return them!
    all_users = [object_to_dict(x) for x in api.get_users()]

    return jsonify(all_users)

@app.route('/users/set_new_password_with_old_password', methods=['POST'])
def user_set_password_with_old():
    """ Sets a new password using the old one. Takes a json body containing
    the keys old_password and new_password. Says ok when done, 401 when not ok.
    You need to be logged in to do this.
    """
    uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if uid == None:
        return abort(401)

    old_password = request.json.get('old_password')
    new_password = request.json.get('new_password')
    successful, _ = api.check_user_password(uid, old_password)
    if successful:
        api.set_user_password(uid, new_password)
        return "ok", 200
    else:
        return "invalid old password", 401

@app.route('/users/set_password_with_key', methods=['POST'])
def user_set_password_with_key():
    """ Sets a new password using a password key that is sent via email.
    Takes a json body containing the keys "key" and "new_password".
    Says ok when done, 401 when not ok. You don't need to be logged in to do this.
    """
    token_str = request.json.get('key')

    uid = token_handler.get_token_user_with_string(token_str)
    if uid == None:
        return abort(401)

    new_password = request.json.get('new_password')
    api.set_user_password(uid, new_password)
    return "ok", 200

@app.route('/users/reset_password', methods=['POST'])
def user_reset_password():
    """ Starts the reset password process by sending a reset mail to the alternative_mail.
    You don't need to be logged in to do this.
    """
    alternative_mail = request.json.get('alternative_mail')
    try:
        user = api.get_user_by_alternative_mail(alternative_mail)
        if user == None:
            # You can't let people guess mails!
            return "ok"
        password_reset_token = token_handler.create_password_reset_jwt_token(user.uid[0]).decode("utf-8")
        mail.send_email(alternative_mail, "Passwort-Reset", "emails/password_reset_email", {
            "name": user.uid[0],
            "link": join(config.FRONTEND_URL, "confirm/password?key=" + password_reset_token),
        })
        return "ok"
    except LdapApiException as e:
        # You can't let people guess mails!
        return "ok"

@app.route('/users/set_alternative_mail', methods=['POST'])
def set_alternative_mail():
    """ Starts the email confirmation process by sending an email.
    Takes a json body with the key "alternative_mail".
    """
    alternative_mail = request.json.get('alternative_mail')
    uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if uid == None:
        return abort(401)
    try:
        email_reset_token = token_handler.create_email_confirmation_jwt_token(uid, alternative_mail).decode("utf-8")
        mail.send_email(alternative_mail, "Email-Confirmation", "emails/email_confirmation", {
            "name": uid,
            "link": join(config.DASHBOARD_URL, "confirm?key=" + email_reset_token),
        })
        return "ok"
    except LdapApiException as e:
        print(e)
        return abort(401)

@app.route('/groups', methods=['GET'])
def groups():
    """ Gets all groups. Returns them as json:
    [
        {
            "businessCategory": "...",
            "cn": "...",
            "ou": "...",
        },
        ...
    ]
    """
    username = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if username == None:
        return abort(401)
    if not api.is_active(username):
        return abort(401)
    groups = [object_to_dict(x) for x in api.get_groups()]
    return jsonify(groups)

@app.route('/my_groups', methods=['GET'])
def mygroups():
    """ Gets all of the groups you are a member of. Returns them as json:
    [
        {
            "businessCategory": "...",
            "cn": "...",
            "ou": "...",
            "membership": "...", // Either "pending", "member", or "admin"
        },
        ...
    ]
    """
    username = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if username == None:
        return abort(401)
    if not api.is_active(username):
        return abort(401)
    pending_groups = [object_to_dict(x) for x in api.get_groups_as_active_pending_member(username)]
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

@app.route('/groups/<group_id>/members', methods=['GET'])
def group_members(group_id):
    group_id = sanitize(group_id)
    uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if uid == None:
        return abort(401)
    if not api.is_active(uid):
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

@app.route('/groups/<group_id>/guests', methods=['GET'])
def group_guests(group_id):
    group_id = sanitize(group_id)
    uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if uid == None:
        return abort(401)
    if not api.is_active(uid):
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

@app.route('/groups/<group_id>/active_pending_members', methods=['GET'])
def group_active_pending_members(group_id):
    group_id = sanitize(group_id)
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not api.is_active(my_uid):
        return abort(401)
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    ldap_members = api.get_group_active_pending_members(group_id)
    members = []
    for x in ldap_members:
        try:
            members.append(object_to_dict(x))
        except Exception as e:
            print(e)
    return jsonify(members)

@app.route('/groups/<group_id>/inactive_pending_members', methods=['GET'])
def group_inactive_pending_members(group_id):
    group_id = sanitize(group_id)
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not api.is_active(my_uid):
        return abort(401)
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    ldap_members = api.get_group_inactive_pending_members(group_id)
    members = []
    for x in ldap_members:
        try:
            members.append(object_to_dict(x))
        except Exception as e:
            print(e)
    return jsonify(members)

@app.route('/groups/<group_id>/owners', methods=['GET'])
def group_owners(group_id):
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not api.is_active(my_uid):
        return abort(401)
    group_id = sanitize(group_id)
    ldap_owners = api.get_group_owners(group_id)
    owners = []
    for x in ldap_owners:
        try:
            owners.append(object_to_dict(x))
        except Exception as e:
            print(e)
    return jsonify(owners)

@app.route('/groups/<group_id>/add_member', methods=['POST'])
def add_user_to_group(group_id):
    group_id = sanitize(group_id)
    uid = sanitize(request.json.get('uid'))
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not api.is_active(my_uid):
        return abort(401)
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    api.add_group_member(group_id, uid)
    return "ok"

@app.route('/groups/<group_id>/remove_member', methods=['POST'])
def remove_user_from_group(group_id):
    """ Removes a user from a group. Call this function if you want to either remove
    yourself from a group or you want to remove another user from a group as an owner.
    If an owner removes a user from allgemein, their entire account is deleted.
    If a user is not part of any group after removal, their entire account is deleted.
    """
    group_id = sanitize(group_id)
    uid = sanitize(request.json.get('uid'))
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not api.is_active(my_uid):
        return abort(401)
    # 1st: Is the uid the group?
    if not (any(x.uid == uid for x in api.get_group_guests(group_id)) or any(x.uid == uid for x in api.get_group_members(group_id))):
        return abort(400)
    # User is not Dashboardadmin, cause dashboardadmin is holy
    if (uid == "dashboardadmin"):
        return abort(400)
    # 2nd: Is the user an admin or just a user
    if any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        # Group owners can remove anyone from a group but themself
        if uid == my_uid:
            return abort(400) # admin tried to remove oneself
        api.remove_group_member(group_id, uid) # remove
        # If user removed from allgemein or from their last group, remove the user
        if group_id == "allgemein" or \
            (api.get_groups_as_member(uid) == [] and api.get_groups_as_owner(uid) == [] and api.get_groups_as_active_pending_member(uid) == []):
            api.delete_user(uid)
        return "ok"
    else:
        # Users can remove themselves from any group but allgemein
        if uid == my_uid and any(x.uid == uid for x in api.get_group_members(group_id)) and not group_id == "allgemein":
            api.remove_group_member(group_id, uid)
            return "ok"
        
    return abort(500)

@app.route('/groups/<group_id>/add_owner', methods=['POST'])
def add_owner_to_group(group_id):
    group_id = sanitize(group_id)
    uid = sanitize(request.json.get('uid'))
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not api.is_active(my_uid):
        return abort(401)
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    api.add_group_owner(group_id, uid)
    return "ok"

@app.route('/groups/<group_id>/remove_owner', methods=['POST'])
def remove_owner_from_group(group_id):
    group_id = sanitize(group_id)
    uid = sanitize(request.json.get('uid'))
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    # Auth is missing
    if my_uid == None:
        return abort(401)
    # User is inactive
    if not api.is_active(my_uid):
        return abort(401)
    # User is not an owner
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    # User is not Dashboardadmin, cause dashboardadmin is holy
    if (uid == "dashboardadmin"):
        return abort(401)
    # User is the ownly owner despite dashboardadmin
    if not any((x.uid != "dashboardadmin" and x.uid != my_uid) for x in api.get_group_owners(group_id)):
        return abort(401)
    api.remove_group_owner(group_id, uid)
    return "ok"

@app.route('/groups/<group_id>/add_guest', methods=['POST'])
def add_guest_to_group(group_id):
    group_id = sanitize(group_id)
    name = sanitize(request.json.get('name'))
    mail = sanitize(request.json.get('mail'))
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not api.is_active(my_uid):
        return abort(401)
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    uid = api.create_guest(name, mail)
    api.add_group_member(group_id, uid)

    group = api.get_group(group_id)
    mail.send_email(str(mail), "Du bist jetzt im Verteiler " + str(group.cn), \
           "emails/guest_invite_email", {
               "name": str(name),
               "group_name": str(group.cn),
           })
    return uid

@app.route('/groups/<group_id>/request_access', methods=['POST'])
def request_access_to_group(group_id):
    group_id = sanitize(group_id)
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not api.is_active(my_uid):
        return abort(401)
    group_request_handler.request_active_pending(api, group_id, my_uid)
    return "ok"

@app.route('/groups/<group_id>/accept_pending_member', methods=['POST'])
def accept_pending_member(group_id):
    group_id = sanitize(group_id)
    uid = sanitize(request.json.get('uid'))
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not api.is_active(my_uid):
        return abort(401)
    if not any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        return abort(401)
    if any(x.uid == uid for x in api.get_group_inactive_pending_members(group_id)):
        api.activate_user(uid)
    api.remove_group_active_pending_member(group_id, uid)
    api.add_group_member(group_id, uid)
    return "ok"

@app.route('/groups/<group_id>/remove_pending_member', methods=['POST'])
def remove_pending_member_from_group(group_id):
    """ Cancels a membership request. Call this function if you want to either remove
    your own membership request from a group or you want to remove another user's request
    from a group as an owner.
    """
    group_id = sanitize(group_id)
    uid = sanitize(request.json.get('uid'))
    my_uid = token_handler.get_jwt_user(request.headers.get('Authorization'))
    if my_uid == None:
        return abort(401)
    if not api.is_active(my_uid):
        return abort(401)
    # Users can remove their own requests from a group
    if uid == my_uid and any(x.uid == uid for x in api.get_group_active_pending_members(group_id)):
        api.remove_group_active_pending_member(group_id, uid)
        return "ok"
    # Group owners can remove any pending member
    if any(x.uid == my_uid for x in api.get_group_owners(group_id)):
        api.remove_group_active_pending_member(group_id, uid)
        return "ok"
    return abort(401)

@app.route('/confirm', methods=['GET'])
def confirm_mail():
    token_str = request.args.get('key')
    token_type = None
    try:
        token = jwt.decode(token_str, config.JWT_SECRET, algorithms=['HS256'])
        if token["type"] == "password_reset":
            pass
        elif token["type"] == "email_confirmation":
            api.set_user_mail(sanitize(token["username"]), sanitize(token["email"]))
        else:
            return abort(400)
        token_type = token["type"]
    except jwt.InvalidTokenError:
        return abort(401)

    redirect_url = None
    if token_type == None:
        return abort(401)
    elif token_type == "password_reset":
        redirect_url = config.FRONTEND_URL + "/confirm/password?key=" + token_str
    elif token_type == "email_confirmation":
        redirect_url = config.FRONTEND_URL + "/confirm/email"
    return redirect(unquote(redirect_url), code=302)
