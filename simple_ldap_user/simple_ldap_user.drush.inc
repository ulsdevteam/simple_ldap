<?php
// From http://stackoverflow.com/a/2510540
function _formatBytes($size, $precision = 2)
{
    $base = log($size) / log(1024);
    $suffixes = array('', 'k', 'M', 'G', 'T');   

    return round(pow(1024, $base - floor($base)), $precision) . $suffixes[floor($base)];
}

/**
 * Implementation of hook_drush_command()
 */
function simple_ldap_user_drush_command() {
  $items = array();
  
  $items['ldap-export-all'] = array(
    'description' => 'Export all users in Drupal that are not in LDAP',
    'callback' => 'simple_ldap_user_drush_export_all',
  );
  $items['ldap-check-all'] = array(
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
    $puid_attr = variable_get('simple_ldap_user_unique_attribute');
    $account = user_load($user['uid'], TRUE);
    $authname = ($puid_attr) ? $ldap_user->{$puid_attr}[0] : $ldap_user->dn;
    user_set_authmaps($account, array('authname_simple_ldap' => $authname));
  }
}

function _simple_ldap_user_drush_missing($authname, $user) {
  $dummy_context = array();
  simple_ldap_user_export_user($user['uid'], $dummy_context);
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
      printf("  %d%% complete (%s)...\r", (int)(100*$user_count / $user_total_count), _formatBytes(memory_get_usage()));
      gc_collect_cycles();
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
    SimpleLdapUser::reset();
    unset($user);
    unset($ldap_user);
  }
  printf("100%% complete (%s / %s)...\nDone\n", _formatBytes(memory_get_usage()), _formatBytes(memory_get_peak_usage()));

  if ($missing_count > 0) {
    drush_log(dt('Found @found with LDAP records.', array('@found' => format_plural($found_count, '1 user', '@count users'))), 'warning');
    drush_log(dt('Missing @missing.', array('@missing' => format_plural($missing_count, '1 user', '@count users'))), 'warning');
    drush_log(dt("Run with --verbose to see the list of missing users."), 'warning');
  } else {
    drush_log(dt('Found all @found', array('@found' => format_plural($found_count, '1 user', '@count users'))), 'ok');
  }
}
