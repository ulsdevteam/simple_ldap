<?php
/**
 * @file
 * Functions for Simple Ldap active_group admin interface.
 */

/**
 * Configuration form.
 */
function simple_ldap_active_group_admin($form, &$form_state) {
  $form = array();

  $form['simple_ldap_active_group_group'] = array(
    '#type' => 'textfield',
    '#title' => t('Default LDAP group'),
    '#default_value' => variable_get('simple_ldap_active_group_group'),
    '#required' => TRUE,
    '#description' => t('This is the group that a user is added to or removed from when the account status is set to active or blocked, respectively.'),
  );

  return system_settings_form($form);
}
