<?php
/**
 * @file
 * Functions for Simple LDAP admin interface.
 */

/**
 * LDAP server configuration form.
 *
 * @todo Require that simple_ldap_pagesize is an integer or empty.
 */
function simple_ldap_admin() {
  $form = array();

  $form['server'] = array(
    '#type' => 'fieldset',
    '#title' => t('LDAP Server Connection Information'),
    '#collapsible' => FALSE,
  );

  $form['server']['simple_ldap_host'] = array(
    '#type' => 'textfield',
    '#title' => t('Host'),
    '#required' => TRUE,
    '#default_value' => variable_get('simple_ldap_host', ''),
    '#description' => t('To use SSL, prepend the host with "ldaps://".'),
  );

  $form['server']['simple_ldap_port'] = array(
    '#type' => 'textfield',
    '#title' => t('Port'),
    '#default_value' => variable_get('simple_ldap_port', '389'),
    '#required' => TRUE,
  );

  $form['server']['simple_ldap_starttls'] = array(
    '#type' => 'checkbox',
    '#title' => t('Use startTLS'),
    '#default_value' => variable_get('simple_ldap_starttls', FALSE),
  );

  $form['server']['simple_ldap_readonly'] = array(
    '#type' => 'checkbox',
    '#title' => t('Read-only'),
    '#default_value' => variable_get('simple_ldap_readonly', FALSE),
  );

  $form['directory'] = array(
    '#type' => 'fieldset',
    '#title' => t('Directory Information'),
    '#collapsible' => FALSE,
  );

  $form['directory']['simple_ldap_binddn'] = array(
    '#type' => 'textfield',
    '#title' => t('Bind DN'),
    '#default_value' => variable_get('simple_ldap_binddn', ''),
    '#description' => t('Leave this blank to bind anonymously'),
  );

  $form['directory']['simple_ldap_bindpw'] = array(
    '#type' => 'password',
    '#title' => t('Bind password'),
    '#description' => t('Leave this blank to bind anonymously'),
    '#attributes' => array('value' => array(variable_get('simple_ldap_bindpw', ''))),
  );

  $form['directory']['simple_ldap_pagesize'] = array(
    '#type' => 'textfield',
    '#title' => t('Search result page size'),
    '#default_value' => variable_get('simple_ldap_pagesize', ''),
    '#description' => t('Leave this blank to disable paged queries.'),
  );

  // Disable the option if paged queries are not supported.
  if (!function_exists('ldap_control_paged_result_response') && !function_exists('ldap_control_paged_result')) {
    $form['directory']['simple_ldap_pagesize']['#disabled'] = TRUE;
    $form['directory']['simple_ldap_pagesize']['#default_value'] = '';
    $form['directory']['simple_ldap_pagesize']['#description'] = t('Paged queries are not supported by this PHP installation.') . ' ' . t('Support was added in PHP version 5.4.');
  }

  return system_settings_form($form);
}
