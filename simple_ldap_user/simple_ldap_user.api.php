<?php
/**
 * @file
 * Describe hooks provided by the Simple LDAP User module.
 */

/**
 * SimpleLdapUser fingerprint.
 *
 * Variables exposed by __get() and __set()
 * ----------------------------------------
 * $attributes
 * $dn
 * $exists
 * $server
 *
 * Magic methods
 * -------------
 * __construct($name)
 * __destruct()
 * __get($name)
 * __set($name, $value)
 *
 * Public functions
 * ----------------
 * authenticate($password)
 * save()
 * delete()
 *
 * Public static methods
 * ---------------------
 * singleton($name)
 * filter()
 * reset()
 * hash($key, $value)
 */

/**
 * Synchronizes a Drupal user to LDAP.
 *
 * This hook is called when simple_ldap_user needs to synchronize Drupal user
 * data to LDAP.
 *
 * This example sets the LDAP employeeType attribute to "full-time"
 *
 * @param StdClass $user
 *   The full Drupal user object that is being synchronized.
 */
function hook_sync_user_to_ldap($user) {
  $ldap_user = SimpleLdapUser::singleton($user->name);
  $ldap_user->employeeType = 'full-time';
  $ldap_user->save();
}
