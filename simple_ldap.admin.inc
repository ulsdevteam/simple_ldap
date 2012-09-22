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

  $form['server']['simple_ldap_hostname'] = array(
    '#type' => 'textfield',
    '#title' => t('Host'),
    '#required' => TRUE,
    '#default_value' => variable_get('simple_ldap_hostname', ''),
  );

  $form['server']['simple_ldap_port'] = array(
    '#type' => 'textfield',
    '#title' => t('Port'),
    '#default_value' => variable_get('simple_ldap_port', '389'),
    '#required' => TRUE,
  );

  $form['server']['simple_ldap_encryption'] = array(
    '#type' => 'radios',
    '#title' => t('Encryption'),
    '#options' => array(
      'none' => t('None'),
      'ssl' => t('SSL'),
      'tls' => t('Start TLS'),
    ),
    '#required' => TRUE,
    '#default_value' => variable_get('simple_ldap_encryption', 'none'),
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
