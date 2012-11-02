<?php
/**
 * @file
 * SimpleLdapRoleController class.
 */

class SimpleLdapRoleController extends SimpleLdapUserController {

  public function attachLoad(&$queried_users, $revision_id = FALSE) {
    parent::attachLoad($queried_users, $revision_id);

    // Get module configuration.
    $basedn = variable_get('simple_ldap_role_basedn');
    $scope = variable_get('simple_ldap_role_scope');
    $attribute_name = variable_get('simple_ldap_role_attribute_name');
    $attribute_member = variable_get('simple_ldap_role_attribute_member');
    $attribute_member_format = variable_get('simple_ldap_role_attribute_member_format');

    // Get an LDAP server object.
    $server = SimpleLdapServer::singleton();

    foreach ($queried_users as $key => $user) {

      // Determine the search string to use.
      if ($attribute_member_format == 'dn') {
        $ldap_user = SimpleLdapUser::singleton($user->name);
        $search = $ldap_user->dn;
      }
      else {
        $search = $user->name;
      }

      // Generate the LDAP search filter.
      $filter = '(&(' . $attribute_member . '=' . $search . ')' . SimpleLdapRole::filter() . ')';

      // Get a list of LDAP groups.
      $ldap_groups = $server->search($basedn, $filter, $scope);

      // Loop through the LDAP groups.
      for ($i = 0; $i < $ldap_groups['count']; $i++) {
        if (!in_array($ldap_groups[$i][$attribute_name][0], $user->roles)) {
          $name = $ldap_groups[$i][$attribute_name][0];
          $drupal_role = user_role_load_by_name($name);

          // The role does not exist, create it.
          if ($drupal_role === FALSE) {
            $drupal_role = new stdClass();
            $drupal_role->name = $name;
            $status = user_role_save($drupal_role);
            $drupal_role = user_role_load_by_name($name);
          }

          $queried_users[$key]->roles[$drupal_role->rid] = $name;
        }
      }
    }

    dpm($queried_users);
  }

}
