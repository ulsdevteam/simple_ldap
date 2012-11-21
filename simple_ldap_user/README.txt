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

* type - This is the field type. Currently, the only supported types are
         'field' and 'default'. 'default' is implied if no type is specified.
	 'field' should be specified for custom fields added to the user
	 object via the Field API.

* drupal - The field name on the Drupal user. This must be the machine name of
	   the field.

* ldap - The LDAP attribute on the LDAP user.

Example:
--------
$conf['simple_ldap_user_attribute_map'] = array(
  // Generic example.
  array(
    'type' => 'field',
    'drupal' => 'drupal-user-field-machine-name',
    'ldap' => 'ldap-attribute',
  ),
  // First name example.
  array(
    'type' => 'field',
    'drupal' => 'field_first_name',
    'ldap' => 'givenName',
  ),
  // Last name example.
  array(
    'type' => 'field',
    'drupal' => 'field_last_name',
    'ldap' => 'sn',
  ),
);

