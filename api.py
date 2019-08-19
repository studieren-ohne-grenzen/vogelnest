from ldap3 import Server, Connection, ALL, MODIFY_ADD, MODIFY_REPLACE, MODIFY_DELETE, HASHED_SALTED_SHA
from ldap3.utils.hashed import hashed
from slugify import slugify

class API():
    def __init__(self, config):
        self.config = config
        server = Server(config.LDAP_HOST, port=config.LDAP_PORT)
        self.conn = Connection(server, config.BIND_DN, config.BIND_PW, auto_bind=False)
        self.conn.start_tls()
        self.conn.bind()

    def get_group_dn(self, ou):
      return 'ou='+ou+','+self.config.DN_GROUPS

    def get_active_person_dn(self, uid):
      return 'uid='+uid+','+self.config.DN_PEOPLE_ACTIVE

    def get_inactive_person_dn(self, uid):
      return 'uid='+uid+','+self.config.DN_PEOPLE_INACTIVE

    def get_guest_dn(self, uid):
      return 'uid='+uid+','+self.config.DN_PEOPLE_GUESTS

    def dn_to_uid(self, dn):
        return dn.split(',', 2)[4:]

    def generate_username(self, name):
        uid = slugify(name, separator='.')
        check = uid
        index = 2
        exists = True
        while(exists):
            try:
                self.find_user_dn(check)
                check = uid + str(index)
                index += 1
            except Exception as e:
                exists = False
        return check

    def find_user_dn(self, uid):
        return self.get_user(uid).entry_dn

    def get_groups(self):
        self.conn.search(self.config.DN_GROUPS, '(objectClass=groupOfNames)', attributes=['ou', 'cn', 'mail'])
        return self.conn.entries

    def get_group(self, uid):
        self.conn.search(DN_GROUPS, '(&(objectClass=groupOfNames)(ou=%s))' % uid, ['cn', 'ou', 'mail'])
        if len(self.conn.entries) > 0:
            return self.conn.entries[0]
        else:
            raise Exception('Cannot find user %s' % uid)

    # Users

    def get_users(self):
        self.conn.search(DN_PEOPLE, 'objectClass=inetOrgPerson', attributes=['cn', 'uid', 'mail'])
        return self.conn.entries

    def get_user(self, uid):
        self.conn.search(DN_PEOPLE, '(&(objectClass=inetOrgPerson)(uid=%s))' % uid, ['cn', 'uid', 'mail'])
        if len(self.conn.entries) > 0:
            return self.conn.entries[0]
        else:
            raise Exception('Cannot find user %s' % uid)

    def create_user(self, firstName, lastName, password, alternativeMail):
        uid = self.generate_username(firstName+ ' '+ lastName)
        new_dn = self.get_inactive_person_dn(uid)
        mail = uid+'@'+self.config.MAIL_DOMAIN
        self.conn.add(new_dn, [
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

    def create_guest(self, name, mail):
        uid = 'guest.'+self.generate_username(name)
        dn = self.get_guest_dn(uid)
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

    def activate_user(self, uid):
        old_dn = self.get_inactive_person_dn(uid)
        pending_groups = self.get_groups_as_pending_member(uid)
        for group in pending_groups:
            self.remove_group_pending_member(group.ou, uid)
        self.conn.modify_dn(old_dn, 'uid=%s' % uid, new_superior=self.config.DN_PEOPLE_ACTIVE)
        for group in pending_groups:
            self.add_group_pending_member(group.ou, uid)

    def delete_user(self, uid):
        dn = self.find_user_dn(uid)
        groups = self.get_groups_as_member(uid)
        for group in groups:
            self.remove_group_member(group.ou, uid)
        owned_groups = self.get_groups_as_owner(uid)
        for group in owned_groups:
            self.remove_group_owner(group.ou, uid)
        self.conn.delete(dn)

    def add_user_mail_alias(self, uid, mail):
        user_dn = self.find_user_dn(uid)
        self.conn.modify(user_dn, {'mailAlias': [(MODIFY_DELETE, [mail])]})
        self.conn.modify(user_dn, {'mailAlias': [(MODIFY_ADD, [mail])]})

    def remove_user_mail_alias(self, uid, mail):
        user_dn = self.find_user_dn(uid)
        self.conn.modify(user_dn, {'mailAlias': [(MODIFY_DELETE, [mail])]})

    def set_user_mail(self, uid, mail):
        user_dn = self.find_user_dn(uid)
        self.conn.modify(user_dn, {'mail-alternative': [(MODIFY_REPLACE, [mail])]})

    def set_user_passsword(self, uid, password):
        user_dn = self.find_user_dn(uid)
        hashed_pw = hashed(HASHED_SALTED_SHA, password)
        self.conn.modify(user_dn, {'userPassword': [(MODIFY_REPLACE, [hashed_pw])]})

    def check_user_passsword(self, uid, password):
        user_dn = self.find_user_dn(uid)
        hashed_pw = hashed(HASHED_SALTED_SHA, password)
        return self.conn.compare(user_dn, 'userPassword', hashed_pw)

    # Groups: pending

    def get_groups_as_pending_member(self, uid):
        user_dn = self.find_user_dn(uid)
        self.conn.search(self.config.DN_GROUPS, '(&(objectClass=groupOfNames)(pending=%s))' % user_dn, attributes=['cn', 'ou', 'mail'])
        return self.conn.entries

    def add_group_pending_member(self, group, uid):
        group_dn = self.get_group_dn(group)
        user_dn = self.find_user_dn(uid)
        self.conn.modify(group_dn, {'pending': [(MODIFY_ADD, [user_dn])]})

    def get_group_pending_members(self, group):
        self.conn.search(DN_GROUPS, '(&(objectClass=groupOfNames)(ou=%s))' % group, attributes=['cn', 'ou', 'pending'])
        if len(self.conn.entries):
            return [self.get_user(self.dn_to_uid(dn)) for dn in self.conn.entries[0].pending.values]
        else:
            raise Exception('Cannot find group %s' % group)

    def remove_group_pending_member(self, group, uid):
        group_dn = self.get_group_dn(group)
        user_dn = self.find_user_dn(uid)
        self.conn.modify(group_dn, {'pending': [(MODIFY_DELETE, [user_dn])]})

    # Groups: member

    def get_groups_as_member(self, uid):
        user_dn = self.find_user_dn(uid)
        self.conn.search(self.config.DN_GROUPS, '(&(objectClass=groupOfNames)(member=%s))' % user_dn, attributes=['cn', 'ou', 'mail'])
        return self.conn.entries

    def add_group_member(self, group, uid):
        group_dn = self.get_group_dn(group)
        user_dn = self.find_user_dn(uid)
        self.conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})

    def get_group_members(self, group):
        self.conn.search(DN_GROUPS, '(&(objectClass=groupOfNames)(ou=%s))' % group, attributes=['cn', 'ou', 'member'])
        if len(self.conn.entries):
            return [self.get_user(self.dn_to_uid(dn)) for dn in self.conn.entries[0].member.values]
        else:
            raise Exception('Cannot find group %s' % group)

    def remove_group_member(self, group, uid):
        group_dn = self.get_group_dn(group)
        user_dn = self.find_user_dn(uid)
        self.conn.modify(group_dn, {'member': [(MODIFY_DELETE, [user_dn])]})

    # Groups: owner

    def get_groups_as_owner(self, uid):
        user_dn = self.find_user_dn(uid)
        self.conn.search(self.config.DN_GROUPS, '(&(objectClass=groupOfNames)(owner=%s))' % user_dn, attributes=['cn', 'ou', 'mail'])
        return self.conn.entries

    def add_group_owner(self, u, uid):
        group_dn = self.get_group_dn(ou)
        user_dn = self.find_user_dn(uid)
        self.conn.modify(group_dn, {'owner': [(MODIFY_ADD, [user_dn])]})
        group = self.get_group(ou)
        if ('mail' in group):
            self.add_user_mail_alias(uid, group.mail)

    def get_group_owners(self, group):
        self.conn.search(DN_GROUPS, '(&(objectClass=groupOfNames)(ou=%s))' % group, attributes=['cn', 'ou', 'owner'])
        if len(self.conn.entries):
            return [self.get_user(self.dn_to_uid(dn)) for dn in self.conn.entries[0].owner.values]
        else:
            raise Exception('Cannot find group %s' % group)

    def remove_group_owner(self, ou, uid):
        group_dn = self.get_group_dn(ou)
        user_dn = self.find_user_dn(uid)
        self.conn.modify(group_dn, {'owner': [(MODIFY_DELETE, [user_dn])]})
        group = self.get_group(ou)
        if ('mail' in group):
            self.remove_user_mail_alias(uid, group.mail)
