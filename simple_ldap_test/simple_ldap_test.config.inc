<?php
/**
 * @file
 * Configuration for the test LDAP server goes here.
 */

// An existing LDAP user for testing.
$ldap_user = array(
  'dn' => 'cn=ldapuser,ou=users,dc=example,dc=com',
  'cn' => 'ldapuser',
  'givenname' => 'LDAP',
  'sn' => 'User',
  'mail' => 'ldapuser@example.com',
  'pass' => 'secret',
);
variable_set('simple_ldap_test_user', $ldap_user);

// An existing LDAP user that deos not match the simple_ldap_user search filter.
$ldap_user = array(
  'dn' => 'cn=inactive,ou=users,dc=example,dc=com',
  'cn' => 'inactive',
  'givenname' => 'Inactive',
  'sn' => 'User',
  'mail' => 'inactive@example.com',
  'pass' => 'secret',
);
variable_set('simple_ldap_test_inactive_user', $ldap_user);

// An existing LDAP group for testing.
$ldap_group = array(
  'dn' => 'cn=ldapgroup,ou=groups,dc=example,dc=com',
  'cn' => 'ldapgroup',
  'member' => 'cn=ldapuser,ou=users,dc=example,dc=com',
);
variable_set('simple_ldap_test_group', $ldap_group);

// From Simple LDAP module.
variable_set('simple_ldap_host', 'ldap.example.com');
variable_set('simple_ldap_port', '389');
variable_set('simple_ldap_binddn', 'cn=admin,dc=example,dc=com');
variable_set('simple_ldap_bindpw', 'supersecret');
variable_set('simple_ldap_starttls', TRUE);
variable_set('simple_ldap_readonly', FALSE);
variable_set('simple_ldap_pagesize', '');

// From Simple LDAP User module.
variable_set('simple_ldap_user_basedn', 'ou=users,dc=example,dc=com');
variable_set('simple_ldap_user_scope', 'sub');
variable_set('simple_ldap_user_objectclass', 'inetOrgPerson');
variable_set('simple_ldap_user_attribute_name', 'cn');
variable_set('simple_ldap_user_attribute_mail', 'mail');
variable_set('simple_ldap_user_attribute_pass', 'userPassword');
variable_set('simple_ldap_user_password_hash', 'salted sha');
variable_set('simple_ldap_user_filter', 'memberOf=cn=active,ou=groups,dc=example,dc=com');
variable_set('simple_ldap_user_source', 'ldap');
variable_set('simple_ldap_user_sync', 'hook_user_load');
variable_set('simple_ldap_user_delete', TRUE);

$map = array(
  array(
    'drupal' => '#field_first_name',
    'ldap' => 'givenname',
  ),
  array(
    'drupal' => '#field_last_name',
    'ldap' => 'sn',
  ),
);

variable_set('simple_ldap_user_map', $map);

// From Simple LDAP Role module.
variable_set('simple_ldap_role_basedn', 'ou=groups,dc=example,dc=com');
variable_set('simple_ldap_role_scope', 'sub');
variable_set('simple_ldap_role_objectclass', 'groupofnames');
variable_set('simple_ldap_role_attribute_name', 'cn');
variable_set('simple_ldap_role_attribute_member', 'member');
variable_set('simple_ldap_role_attribute_member_format', 'dn');
variable_set('simple_ldap_role_attribute_member_default', 'cn=default,ou=users,dc=example,dc=com');
variable_set('simple_ldap_role_filter', '');
variable_set('simple_ldap_role_source', 'ldap');
variable_set('simple_ldap_role_sync', 'hook_user_load');
