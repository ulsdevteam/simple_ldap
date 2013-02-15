Simple LDAP Role
================

This module allows Drupal roles to be derived from LDAP groups, and
vice-versa. It is dependent on the Simple LDAP User module.

Testing
=======

In order to successfully run simpletest against this module, the following
variable needs to be defined in settings.php

$conf['simple_ldap_role_test_group']

It is a keyed array of LDAP attribute names to LDAP attribute values of an
existing LDAP entry to use for testing. 'dn' is a required attribute, and the
other attributes should be defined according to what is configured for
simple_ldap_role.

Example:
$conf['simple_ldap_role_test_group'] = array(
  'dn' => 'cn=ldapgroup,ou=groups,dc=example,dc=com',
  'cn' => 'ldapgroup',
  'member' => 'cn=ldapuser,ou=users,dc=example,dc=com',
);
