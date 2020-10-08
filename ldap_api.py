from ldap3 import Server, Connection, ALL, MODIFY_ADD, MODIFY_REPLACE, MODIFY_DELETE, HASHED_SALTED_SHA
from ldap3.utils.hashed import hashed
from ldap3.core.exceptions import LDAPBindError
from slugify import slugify
import config

USER_ATTRIBUTES = ['uid', 'cn', 'mail']
GROUP_ATTRIBUTES = ['ou', 'cn', 'businessCategory']
GROUP_ATTRIBUTES_SPECIAL = ['ou', 'cn', 'owner', 'member']

class LdapApiException(Exception):
    pass

class LdapApi():
    def __init__(self, config):
        self.config = config
        self.server = Server(config.LDAP_HOST, port=config.LDAP_PORT, allowed_referral_hosts=[('*', True)])
        self.conn = Connection(self.server, config.BIND_DN, config.BIND_PW, auto_bind=True)
        self.conn.start_tls()
        self.conn.bind()
        print("Connected to LDAP server!")

    def get_group_dn(self, ou):
        return 'ou='+ou+','+self.config.DN_GROUPS

    def get_active_person_dn(self, uid):
        return 'uid='+uid+','+self.config.DN_PEOPLE_ACTIVE

    def get_inactive_person_dn(self, uid):
        return 'uid='+uid+','+self.config.DN_PEOPLE_INACTIVE

    def get_guest_dn(self, uid):
        return 'uid='+uid+','+self.config.DN_PEOPLE_GUESTS

    def dn_to_uid(self, dn):
        return dn.split(',')[0][4:]

    def generate_username(self, name):
        uid = slugify(name, separator='.', replacements=
                      [
                          ["ü", "ue"],
                          ["ä", "ae"],
                          ["ö", "oe"],
                          ["ß", "ss"],
                      ]
                      )
        check = uid
        index = 2
        exists = True
        while(exists):
            exists = self.conn.search(config.DN_PEOPLE, '(&(objectClass=inetOrgPerson)(uid=%s))' % check)
            if exists:
                check = uid + str(index)
                index += 1
        return check

    def find_user_dn(self, uid):
        return self.get_user(uid).entry_dn

    def get_groups(self):
        self.conn.search(self.config.DN_GROUPS, '(objectClass=groupOfNames)', attributes=GROUP_ATTRIBUTES)
        return self.conn.entries
    
    def get_group(self, uid):
        self.conn.search(config.DN_GROUPS, '(&(objectClass=groupOfNames)(ou=%s))' % uid, attributes=GROUP_ATTRIBUTES)
        if len(self.conn.entries) > 0:
            return self.conn.entries[0]
        else:
            raise LdapApiException('Cannot find user %s' % uid)

    # Users

    def get_users(self):
        self.conn.search(config.DN_PEOPLE_ACTIVE, '(objectClass=inetOrgPerson)', attributes=USER_ATTRIBUTES)
        return self.conn.entries

    def get_user(self, uid):
        self.conn.search(config.DN_PEOPLE, '(&(objectClass=inetOrgPerson)(uid=%s))' % uid, attributes=USER_ATTRIBUTES)
        if len(self.conn.entries) > 0:
            return self.conn.entries[0]
        else:
            raise LdapApiException('Cannot find user %s' % uid)

    def get_user_by_alternative_mail(self, alternative_mail):
        self.conn.search(config.DN_PEOPLE, '(&(objectClass=inetOrgPerson)(mail-alternative=%s))' % alternative_mail, attributes=USER_ATTRIBUTES)
        if len(self.conn.entries) > 0:
            return self.conn.entries[0]
        else:
            raise LdapApiException('Cannot find user with  %s' % alternative_mail)

    def get_user_info(self, uid):
        detailed_user_attributes = [
            'uid',
            'cn',
            'mail',
            'mail-alternative',
            'sn',
            'displayName',
            'givenName',
            'mailEnabled'
        ]
        self.conn.search(config.DN_PEOPLE, '(&(objectClass=inetOrgPerson)(uid=%s))' % uid, attributes=detailed_user_attributes)
        if len(self.conn.entries) > 0:
            return self.conn.entries[0]
        else:
            raise LdapApiException('Cannot find user %s' % uid)

    def create_guest(self, name, mail):
        uid = self.generate_username('guest.' + name)
        dn = self.get_guest_dn(uid)
        self.conn.add(dn, [
            'inetOrgPerson',
            'top',
        ], {
            'uid': uid,
            'displayName': 'Guest %s' % name,
            'cn': 'Guest %s' % name,
            'givenName': 'Guest %s' % name,
            'sn': 'Guest %s' % name,
            'mail': mail
        })

        if self.conn.result['result'] != 0:
            raise RuntimeError(self.conn.result)
        return uid

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

    def set_user_password(self, uid, password):
        user_dn = self.find_user_dn(uid)
        hashed_pw = hashed(HASHED_SALTED_SHA, password)
        self.conn.modify(user_dn, {'userPassword': [(MODIFY_REPLACE, [hashed_pw])]})

    def set_user_alternative_mail(self, uid, alternative_mail):
        user_dn = self.find_user_dn(uid)
        self.conn.modify(user_dn, {'mail-alternative': [(MODIFY_REPLACE, [alternative_mail])]})

    def check_user_password(self, uid, password):
        successful = False
        try:
            user_dn = self.find_user_dn(uid)
            new_server = Server(config.LDAP_HOST, port=config.LDAP_PORT, allowed_referral_hosts=[('*', True)])
            new_conn = Connection(new_server, user_dn, password, auto_bind=True)
            new_conn.bind()
            new_conn.unbind()
            successful = True
        except (LDAPBindError, LdapApiException) as e:
            print(e)
            successful = False
            pass
        
        return successful
        
    # Groups: pending
    def get_groups_as_pending_member(self, uid):
        user_dn = self.find_user_dn(uid)
        self.conn.search(self.config.DN_GROUPS, '(&(objectClass=groupOfNames)(pending=%s))' % user_dn, attributes=GROUP_ATTRIBUTES)
        return self.conn.entries

    def add_group_pending_member(self, group, uid):
        group_dn = self.get_group_dn(group)
        user_dn = self.find_user_dn(uid)
        self.conn.modify(group_dn, {'pending': [(MODIFY_ADD, [user_dn])]})

    def get_group_pending_members(self, group):
        self.conn.search(config.DN_GROUPS, '(&(objectClass=groupOfNames)(ou=%s))' % group, attributes=GROUP_ATTRIBUTES)
        if len(self.conn.entries):
            group_members = []
            if not "values" in self.conn.entries[0]:
                return []
            for dn in self.conn.entries[0].pending.values:
                try:
                    group_members.append(self.get_user(self.dn_to_uid(dn)))
                # this happens
                except LdapApiException:
                    print(dn, "does not exist")
            return group_members
        else:
            raise LdapApiException('Cannot find group %s' % group)

    def remove_group_pending_member(self, group, uid):
        group_dn = self.get_group_dn(group)
        user_dn = self.find_user_dn(uid)
        self.conn.modify(group_dn, {'pending': [(MODIFY_DELETE, [user_dn])]})

    # Groups: member

    def get_groups_as_member(self, uid):
        user_dn = self.find_user_dn(uid)
        self.conn.search(self.config.DN_GROUPS, '(&(objectClass=groupOfNames)(member=%s))' % user_dn, attributes=GROUP_ATTRIBUTES)
        return self.conn.entries

    def add_group_member(self, group, uid):
        group_dn = self.get_group_dn(group)
        user_dn = self.find_user_dn(uid)
        self.conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})

    def get_group_members(self, group):
        group_dn = self.get_group_dn(group)
        self.conn.search(config.DN_PEOPLE_ACTIVE, '(&(objectClass=inetOrgPerson)(memberOf=%s))' % group_dn, attributes=USER_ATTRIBUTES)
        return self.conn.entries

    def get_group_guests(self, group):
        group_dn = self.get_group_dn(group)
        self.conn.search(config.DN_PEOPLE_GUESTS, '(&(objectClass=inetOrgPerson)(memberOf=%s))' % group_dn, attributes=USER_ATTRIBUTES)
        return self.conn.entries

    def remove_group_member(self, group, uid):
        group_dn = self.get_group_dn(group)
        user_dn = self.find_user_dn(uid)
        self.conn.modify(group_dn, {'member': [(MODIFY_DELETE, [user_dn])]})

    # Groups: owner

    def get_groups_as_owner(self, uid):
        user_dn = self.find_user_dn(uid)
        self.conn.search(self.config.DN_GROUPS, '(&(objectClass=groupOfNames)(owner=%s))' % user_dn, attributes=GROUP_ATTRIBUTES)
        return self.conn.entries

    def add_group_owner(self, ou, uid):
        group_dn = self.get_group_dn(ou)
        user_dn = self.find_user_dn(uid)
        self.conn.modify(group_dn, {'owner': [(MODIFY_ADD, [user_dn])]})
        group = self.get_group(ou)
        if ('mail' in group):
            self.add_user_mail_alias(uid, group.mail)

    def get_group_owners(self, group):
        self.conn.search(config.DN_GROUPS, '(&(objectClass=groupOfNames)(ou=%s))' % group, attributes=GROUP_ATTRIBUTES_SPECIAL)
        if len(self.conn.entries):
            group_owners = []
            for dn in self.conn.entries[0].owner.values:
                try:
                    group_owners.append(self.get_user(self.dn_to_uid(dn)))
                # this happens
                except LdapApiException:
                    print(dn, "does not exist")
            return group_owners
        else:
            raise LdapApiException('Cannot find group %s' % group)

    def is_group_owner_anywhere(self, uid):
        self.conn.search(self.config.DN_GROUPS, '(objectClass=groupOfNames)', attributes=["owner"])
        for entry in self.conn.entries:
            for owner in entry.owner:
                if self.dn_to_uid(owner) == uid:
                    return True
        return False


    def remove_group_owner(self, ou, uid):
        group_dn = self.get_group_dn(ou)
        user_dn = self.find_user_dn(uid)
        self.conn.modify(group_dn, {'owner': [(MODIFY_DELETE, [user_dn])]})
        group = self.get_group(ou)
        if ('mail' in group):
            self.remove_user_mail_alias(uid, group.mail)
