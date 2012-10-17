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

      if ($ldap_user->exists()) {
        // Load the attribute map.
        $map = simple_ldap_user_map();

        // Synchronize attributes.
        switch (simple_ldap_user_sync()) {

          // Synchronize attributes ldap->drupal.
          case 'ldap':
            $users[$uid] = $this->syncLdapToDrupal($drupal_user, $ldap_user);
            break;

          // Synchronize attributes drupal->ldap.
          case 'drupal':
            $this->syncDrupalToLdap($drupal_user, $ldap_user);
            break;

        }

      }
      else {
        // Block the user if it does not exist in LDAP.
        $users[$uid]->status = 0;
      }

    }

    return $users;
  }

  /**
   * Synchronizes LDAP attributes to Drupal user properties.
   */
  protected function syncLdapToDrupal(stdClass $drupal_user, SimpleLdapUser $ldap_user) {
    // Initialize array of attribute changes.
    $edit = array();

    // Mail is a special attribute.
    $mail = variable_get('simple_ldap_user_attribute_mail');
    if ($drupal_user->mail != $ldap_user->{$mail}[0]) {
      $edit['mail'] = $ldap_user->{$mail}[0];
    }

    // Synchronize other mapped attributes.
    if (!empty($map)) {
      foreach ($map as $attribute) {
        $attribute['ldap'] = strtolower($attribute['ldap']);

        // Verify that the user field exists.
        if (isset($drupal_user->$attribute['drupal'])) {
          switch ($attribute['type']) {

            // Update the value in drupal using Field API.
            case 'field':
              // Get the Drupal field values and metadata.
              $items = field_get_items('user', $drupal_user, $attribute['drupal']);
              $info = field_info_field($attribute['drupal']);
              $language = field_language('user', $drupal_user, $attribute['drupal']);

              // Sync field data from LDAP data.
              $dirty = FALSE;
              for ($i = 0; $i < $ldap_user->{$attribute['ldap']}['count']; $i++) {
                if ($i < $info['cardinality'] || $info['cardinality'] == FIELD_CARDINALITY_UNLIMITED) {
                  $edit[$attribute['drupal']][$language][$i]['value'] = $ldap_user->{$attribute['ldap']}[$i];
                  if ($items[$i]['value'] != $ldap_user->{$attribute['ldap']}[$i]) {
                    $dirty = TRUE;
                  }
                }
              }

              // Check if any changes were actually made.
              if (!$dirty) {
                unset($edit[$attribute['drupal']]);
              }
              break;

            // Update the value directly on the user object.
            case 'default':
            default:
              if ($drupal_user->$attribute['drupal'] != $ldap_user->{$attribute['ldap']}[0]) {
                $edit[$attribute['drupal']] = $ldap_user->{$attribute['ldap']}[0];
              }
              break;

          }
        }

      }
    }

    // Save any changes.
    if (!empty($edit)) {
      // Clone $drupal_user into $drupal_user->original in order to avoid an
      // infinite loop.
      $drupal_user->original = clone $drupal_user;
      $drupal_user = user_save($drupal_user, $edit);
    }

    return $drupal_user;
  }

  /**
   * Synchronizes Drupal user properties to LDAP.
   */
  protected function syncDrupalToLdap(stdClass $drupal_user, SimpleLdapUser $ldap_user) {
  }

}
