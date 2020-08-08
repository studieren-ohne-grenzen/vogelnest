def dn_to_uid(dn):
    return dn.split(',')[0][4:]

def group_to_dict(group):
    return {
        "ou": group.ou[0],
        "name": group.cn[0],
        "groupType": "others" if len(group.businessCategory) == 0 else group.businessCategory[0]
    }

def user_to_dict(user):
    return {
        "uid": user.uid[0],
        "name": user.cn[0],
        "mail": user.mail[0],
    }

