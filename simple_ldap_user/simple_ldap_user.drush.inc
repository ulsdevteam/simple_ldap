<?php

/**
 * Implementation of hook_drush_command()
 */
function simple_ldap_user_drush_command() {
  $items = array();
  
  $items['ldap_export_all'] = array(
    'description' => 'Export all users in Drupal that are not in LDAP',
    'callback' => 'simple_ldap_user_drush_export_all',
  );
  $items['ldap_check_all'] = array(
    'description' => 'Check all users in Drupal are in LDAP',
    'callback' => 'simple_ldap_user_drush_check_all',
  );
  return $items;
}

function simple_ldap_user_drush_check_all() {
  return simple_ldap_user_drush_scan_all();
}

function simple_ldap_user_drush_export_all() {
  return simple_ldap_user_drush_scan_all('_simple_ldap_user_drush_found', '_simple_ldap_user_drush_missing');
}

function _simple_ldap_user_drush_found($authname, $user, $ldap_user) {
  if (empty($authname)) {
    $account = user_load($user['uid']);
    user_set_authmaps($account, array('authname_simple_ldap' => $ldap_user->dn));
  }
}

function _simple_ldap_user_drush_missing($authname, $user) {
  $context = array();
  simple_ldap_user_export_user($user['uid'], $context);
  drush_log(dt('Provisioning @user', array('@user' => $user['name'])), 'ok');
}

function simple_ldap_user_drush_scan_all($found_callback = NULL, $not_found_callback = NULL) {
  $user_total_count = db_query("SELECT COUNT(*) AS count FROM {users}")->fetchAssoc();
  $user_total_count = $user_total_count['count'];
  $sql = "SELECT * FROM {users} u";

  $result = db_query($sql);
  if (!$result) {
    drush_log(dt('Failed to fetch list of users from Drupal database.'), 'error');
    return;
  }

  $user_count = $found_count = $missing_count = 0;

  while($user = $result->fetchAssoc()) {
    if ($user['uid'] < 2) {
      continue;
    }

    $user_count++;
    if (($user_count % 1024) == 0) {
      printf("%d%% complete...\r", (int)(100*$user_count / $user_total_count));
    }

    $authname = db_query("SELECT authname FROM {authmap} WHERE uid=:uid", array(':uid' => $user['uid']))->fetchAssoc();
    $ldap_user = SimpleLdapUser::singleton($user['name']);

    if (($ldap_user->exists)) {
      drush_log(dt("Found @user (@dn)", array('@user' => $user['name'], '@dn' => $ldap_user->dn)), 'debug');
      if (!empty($found_callback)) {
        $found_callback($authname, $user, $ldap_user);
      }
      $found_count++;
    }
    else {
      drush_log(dt("Missing @user (@dn)", array('@user' => $user['name'], '@dn' => $authname)), 'notice');
      if (!empty($not_found_callback)) {
        $not_found_callback($authname, $user);
      }
      $missing_count++;
    }
    SimpleLdapUser::reset($user['name']);
  }
  printf("100%% complete...\nDone\n");

  if ($missing_count > 0) {
    drush_log(dt('Found @found with LDAP records.', array('@found' => format_plural($found_count, '1 user', '@count users'))), 'warning');
    drush_log(dt('Missing @missing.', array('@missing' => format_plural($missing_count, '1 user', '@count users'))), 'warning');
    drush_log(dt("Run with --verbose to see the list of missing users."), 'warning');
  } else {
    drush_log(dt('Found all @found', array('@found' => format_plural($found_count, '1 user', '@count users'))), 'ok');
  }

}