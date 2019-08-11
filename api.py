from ldap3 import Server, Connection, ALL, MODIFY_ADD, MODIFY_REPLACE, MODIFY_DELETE, HASHED_SALTED_SHA
from ldap3.utils.hashed import hashed
from config import LDAP_HOST, LDAP_PORT, BIND_DN, BIND_PW, MAIL_DOMAIN, \
 DN_GROUPS, DN_PEOPLE, DN_PEOPLE_ACTIVE, DN_PEOPLE_INACTIVE
from slugify import slugify

server = Server(LDAP_HOST, port=LDAP_PORT)
conn = Connection(server, BIND_DN, BIND_PW, auto_bind=False)
conn.start_tls()
conn.bind()

def get_group_dn(ou):
  return 'ou='+ou+','+DN_GROUPS

def get_active_person_dn(uid):
  return 'uid='+uid+','+DN_PEOPLE_ACTIVE

def get_inactive_person_dn(uid):
  return 'uid='+uid+','+DN_PEOPLE_INACTIVE

def get_guest_dn(uid):
  return 'uid='+uid+','+DN_PEOPLE_GUESTS

def dn_to_uid(dn):
    return dn.split(',', 2)[4:]

def generate_username(name):
    uid = slugify(name, separator='.')
    check = uid
    index = 2
    exists = True
    while(exists):
        try:
            find_user_dn(check)
            check = uid + str(index)
            index += 1
        except Exception as e:
            exists = False
    return check

def find_user_dn(uid):
    conn.search(DN_PEOPLE, '(&(objectClass=inetOrgPerson)(uid=%s))' % uid)
    if len(conn.entries) > 0:
        return conn.entries[0].entry_dn
    else:
        raise Exception('Cannot find user %s' % uid)

def get_groups():
    conn.search(DN_GROUPS, '(objectClass=groupOfNames)', attributes=['cn', 'mail'])
    return conn.entries

def get_users():
    conn.search(DN_PEOPLE, 'objectClass=inetOrgPerson', attributes=['cn', 'uid', 'mail'])
    return conn.entries

def create_user(firstName, lastName, password, alternativeMail):
    uid = generate_username(firstName+ ' '+ lastName)
    new_dn = get_inactive_person_dn(uid)
    mail = uid+'@'+MAIL_DOMAIN
    conn.add(new_dn, [
            'person',
            'sogperson',
            'organizationalPerson',
            'inetOrgPerson',
            'top',
            'PostfixBookMailAccount',
            'PostfixBookMailForward'
        ], {
      'uid': uid,
      'displayName': firstName + " " + lastName,
      'cn': firstName + " " + lastName,
      'givenName': firstName,
      'sn': lastName,
      'userPassword': hashed(HASHED_SALTED_SHA, password),
      'mail': mail,
      'mail-alternative': alternativeMail,
      'mailHomeDirectory': '/srv/vmail/%s' % mail,
      'mailStorageDirectory': 'maildir:/srv/vmail/%s/Maildir' % mail,
      'mailEnabled': 'TRUE',
      'mailGidNumber': 5000,
      'mailUidNumber': 5000
    })
    return uid

def create_guest(name, mail):
    uid = 'guest.'.generate_username(name)
    dn = get_guest_dn(uid)
    conn.add(new_dn, [
            'inetOrgPerson',
            'top',
        ], {
      'uid': uid,
      'displayName': 'Guest %s' % name,
      'cn': 'Guest %s' % name,
      'givenName': 'Guest %s' % name,
      'sn': 'Guest %s' % name,
      'mail': 'mail'
    })

def delete_user(uid):
    dn = find_user_dn(uid)
    groups = get_groups_as_member(uid)
    for group in groups:
        remove_group_member(group.ou, uid)
    owned_groups = get_groups_as_owner(uid)
    for group in owned_groups:
        remove_group_owner(group.ou, uid)
    conn.delete(dn)

def add_user_mail_alias(uid, mail):
    user_dn = find_user_dn(uid)
    conn.modify(user_dn, {'mailAlias': [(MODIFY_DELETE, [mail])]})
    conn.modify(user_dn, {'mailAlias': [(MODIFY_ADD, [mail])]})

def remove_user_mail_alias(uid, mail):
    user_dn = find_user_dn(uid)
    conn.modify(user_dn, {'mailAlias': [(MODIFY_DELETE, [mail])]})

def set_user_mail(uid, mail):
    user_dn = find_user_dn(uid)
    conn.modify(user_dn, {'mail-alternative': [(MODIFY_REPLACE, [mail])]})

def set_user_passsword(uid, password):
    user_dn = find_user_dn(uid)
    hashed_pw = hashed(HASHED_SALTED_SHA, password)
    conn.modify(user_dn, {'userPassword': [(MODIFY_REPLACE, [hashed_pw])]})

def get_groups_as_member(uid):
    user_dn = find_user_dn(uid)
    conn.search(DN_GROUPS, '(&(objectClass=groupOfNames)(member=%s))' % user_dn, attributes=['cn', 'ou', 'mail'])
    return conn.entries

def add_group_member(group, uid):
    group_dn = get_group_dn(group)
    user_dn = find_user_dn(uid)
    conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})

def get_group_members(group):
    conn.search(DN_GROUPS, '(&(objectClass=groupOfNames)(ou=%s))' % group, attributes=['cn', 'ou', 'member'])
    if len(conn.entries):
        return [dn_to_uid(dn) for dn in conn.entries[0].member.values]
    else:
        raise Exception('Cannot find group %s' % group)

def remove_group_member(group, uid):
    group_dn = get_group_dn(group)
    user_dn = find_user_dn(uid)
    conn.modify(group_dn, {'member': [(MODIFY_DELETE, [user_dn])]})

def get_groups_as_owner(uid):
    user_dn = find_user_dn(uid)
    conn.search(DN_GROUPS, '(&(objectClass=groupOfNames)(owner=%s))' % user_dn, attributes=['cn', 'ou', 'mail'])
    return conn.entries

def add_group_owner(group, uid):
    group_dn = get_group_dn(group)
    user_dn = find_user_dn(uid)
    conn.modify(group_dn, {'owner': [(MODIFY_ADD, [user_dn])]})

def get_group_owners(group):
    conn.search(DN_GROUPS, '(&(objectClass=groupOfNames)(ou=%s))' % group, attributes=['cn', 'ou', 'owner'])
    if len(conn.entries):
        return [dn_to_uid(dn) for dn in conn.entries[0].owner.values]
    else:
        raise Exception('Cannot find group %s' % group)

def remove_group_owner(group, uid):
    group_dn = get_group_dn(group)
    user_dn = find_user_dn(uid)
    conn.modify(group_dn, {'owner': [(MODIFY_DELETE, [user_dn])]})
