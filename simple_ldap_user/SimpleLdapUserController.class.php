<?php
/**
 * @file
 * SimpleLdapUserController class.
 */

/**
 * Controller class for LDAP users.
 */
class SimpleLdapUserController extends UserController {

  /**
   * Verifies that the user exists in the LDAP directory.
   */
  public function load($ids = array(), $conditions = array()) {
    $users = parent::load($ids, $conditions);

    // Get LDAP server configurations.
    $server = SimpleLdapServer::singleton();
    $search = strtolower(variable_get('simple_ldap_user_attribute_name'));
    $base_dn = variable_get('simple_ldap_user_basedn');
    $scope = variable_get('simple_ldap_scope');

    // Validate users against LDAP directory.
    foreach ($users as $uid => $drupal_user) {
      // Do not validate user/1, anonymous users, or blocked users.
      if ($uid == 1 || $uid == 0 || $drupal_user->status == 0) {
        continue;
      }

      // Try to load the user from LDAP.
      $ldap_user = SimpleLdapUser::singleton($drupal_user->name);

      // Block the user if it does not exist in LDAP.
      if (!$ldap_user->exists()) {
        $users[$uid]->status = 0;
      }

    }

    return $users;
  }
}
