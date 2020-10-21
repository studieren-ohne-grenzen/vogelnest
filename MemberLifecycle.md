# Member Lifecycle

Members are reflected in CiviCRM, a drupal based CRM system *and* LDAP. The LDAP is administered thru vogelnest.

## User Creation
At SOG, members don't sign up via vogelnest. They are signed up / sign up themselves in CiviCRM.
The repo sogintegration is the module which performs the SOG specific parts of member sign up.
Being:
  - creating a SEPA direct debit mandate
  - creating a user in the LDAP tree
  
The requirements to vogelnest in this process are:
  - upon a request from CiviCRM:
    - create a user in the LDAP tree
    - choose a unique username
    - add the new user to it's LG and to Allgemein as pending inactives
    - notify ppl to activate the user
    - invite the user to choose a password
    - reflect the newly choosen username back to CiviCRM; CiviCRM will save the mail adress in the SOG domain

### Technical Documentation

CiviCRM drops a request to the endpoint *create_user* using POST.
The following info shall be delivered in a JSON body:
  - First Name
  - Last Name
  - E-Mail
  - Lokalgruppe (prefixed lowercase, like lg_aachen or lg_berlin)

Since only Civi may create users, the request has to be authenticated
by HTTP basic auth.
Username: *civicrm*
Password: As specified in CIVICRM_SECRET

This app will generate a username and return it as plain text
in the response body.

This app will issue error 500 if user creation is not possible.
    
## Other requirements in the member lifecycle
- Changes in the alternative e mail adress shall be reflected (see #28)
- Members could change their names (see #29)
- Members may leave the organisation (see #30)
