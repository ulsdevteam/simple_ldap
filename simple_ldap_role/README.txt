Simpletests:
============

X Create a role in Drupal
	- If default user, created in LDAP
	- If no default user
		- If member field not required, created in LDAP
		- If member field required, do nothing

X Edit role in Drupal
	- Role updated in LDAP

* Delete role in Drupal
	- Delete LDAP group

* Add role to user in Drupal (Format: dn/name)
	- If group exists, add user
	- If group does not exist, create and add user

* Remove role from user in Drupal (Format: dn/name)
	- If more members, remove user
	- If last user
		- If member field required
			- If default user configured, add it and remove user from group.
			- If no default user, delete the group.
		- If member field not required, remove user

* Create a group in LDAP
	- Drupal role created on cron run

* Edit a group in LDAP
	- Drupal role created on cron run

* Delete a group in LDAP
	- No action

* Add a user to a group in LDAP
	- Role is added to Drupal user (hook_user_login, hook_user_load)

* Remove a user from a group in LDAP
	- Role is removed from Drupal user (hook_user_login, hook_user_load)
