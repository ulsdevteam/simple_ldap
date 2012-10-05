<?php
/**
 * @file
 * Functions for Simple LDAP admin interface.
 */

/**
 * LDAP server configuration form.
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

  // @todo Check whether the server supports paged queries. Look for the oid
  // "1.2.840.113556.1.4.319" in the $server->rootdse['supportedcontrol'].
  $form['directory']['simple_ldap_pagesize'] = array(
    '#type' => 'textfield',
    '#title' => t('Search result page size'),
    '#default_value' => variable_get('simple_ldap_pagesize', ''),
    '#description' => t('Leave this blank to disable paged queries.'),
  );

  return system_settings_form($form);
}
