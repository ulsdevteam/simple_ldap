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

// Visit /admin/config/people/simple_ldap/simpletest to get a listing of
// variables needed to configure the simpletest to work in the same manner as
// the real modules. Paste the output from that URL here:
