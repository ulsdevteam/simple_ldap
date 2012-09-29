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
    '#title' => t('LDAP Server'),
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
    '#description' => t('Leave this blank to bind anonymously'),
    '#default_value' => variable_get('simple_ldap_binddn', ''),
  );

  $form['directory']['simple_ldap_bindpw'] = array(
    '#type' => 'password',
    '#title' => t('Bind Password'),
    '#description' => t('Leave this blank to bind anonymously'),
    '#attributes' => array('value' => array(variable_get('simple_ldap_bindpw', ''))),
  );

  return system_settings_form($form);
}
