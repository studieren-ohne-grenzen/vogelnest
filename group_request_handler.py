import mail
import config

def request_active_pending(api, group_id, my_uid):
    api.add_group_active_pending_member(group_id, my_uid)
    group = api.get_group(group_id)
    user = api.get_user(my_uid)
    for owner in api.get_group_owners(group_id):
        mail.send_email(str(owner.mail), "Neue Anfrage in " + str(group.cn), \
               "emails/new_pending_member_mail", {
                   "name": str(owner.cn),
                   "group_name": str(group.cn),
                   "dashboard_url": config.FRONTEND_URL,
                   "new_member_name": str(user.cn)
               })