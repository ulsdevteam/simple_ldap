Simple LDAP User
================

This module allows authentication to the LDAP directory configured in the
Simple LDAP module. It also provides synchronization services both to and from
LDAP and Drupal. It supports mapping LDAP attributes to Drupal user object
fields (both native, and using Field API).

Configuration
=============

In addition to the configuration available in the administration UI, an
attribute map can be specified in settings.php, using the variable
$conf['simple_ldap_user_attribute_map'].

This variable is an array of arrays, where each of the arrays have the
following items:

* drupal - The field name on the Drupal user. This must be the machine name of
	   the field.

	   This can also be an array of drupal fields. If the array contains
	   more than one entry, synchronization for that map only works in the
	   drupal->ldap direction, and the fields are concatenated with a
	   space separator.

           A field type can be specified by prefixing the field name. If no
	   prefix is given, it is assumed that the field is a direct user
	   object attribute, such as uid, name, or pass.

	   # - Custom fields added to the user object via the Field API.

* ldap - The LDAP attribute on the LDAP user.

Example:
--------
$conf['simple_ldap_user_attribute_map'] = array(

  // Generic example.
  array(
    'drupal' => '#drupal-user-field-machine-name',
    'ldap' => 'ldap-attribute',
  ),

  // First name example.
  array(
    'drupal' => '#field_first_name',
    'ldap' => 'givenName',
  ),

  // Last name example.
  array(
    'drupal' => '#field_last_name',
    'ldap' => 'sn',
  ),

  // Timezone example (saved directly to users table, note there is no '#').
  array(
    'drupal' => 'timezone',
    'ldap' => 'l',
  ),

  // Combined fields example.
  array(
    'drupal' => array(
      '#field_first_name',
      '#field_last_name',
    ),
    'ldap' => 'displayName',
  ),

);

Testing
=======

In order to successfully run simpletest against this module, the following
variables need to be defined in settings.php.

$conf['simple_ldap_user_test_active_user']
$conf['simple_ldap_user_test_blocked_user']

Both variables are of the same structure. They are a keyed array of LDAP
attribute name to LDAP attribute value of existing LDAP entries to use for
testing. 'dn' is a required attribute, and the other attributes should be
defined according to what is configured for simple_ldap_user.

The blocked_user array is only needed if an LDAP filter is specified in the
configuration. If present, this user should be an existing LDAP entry that
does not match the filter.

Example:
$conf['simple_ldap_user_test_active_user'] = array(
  'dn' => 'cn=ldapuser,dc=users,dc=example,dc=com',
  'cn' => 'ldapuser',
  'givenname' => 'LDAP',
  'sn' => 'User',
  'mail' => 'ldapuser@example.com',
  'pass' => 'secret',
);
$conf['simple_ldap_user_test_blocked_user'] = array(
  'dn' => 'cn=inactive,ou=users,dc=example,dc=com',
  'cn' => 'inactive',
  'givenname' => 'Inactive',
  'sn' => 'User',
  'mail' => 'inactive@example.com',
  'pass' => 'secret',
);
