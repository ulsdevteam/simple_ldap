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
