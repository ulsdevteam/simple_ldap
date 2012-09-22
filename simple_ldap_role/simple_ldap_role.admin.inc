<?php
/**
 * @file
 * Functions for Simple LDAP Role admin interface.
 */

/**
 * Simple LDAP Role configuration form.
 */
function simple_ldap_role_admin() {
  $form = array();

  $form['role'] = array(
    '#type' => 'fieldset',
    '#title' => t('LDAP Roles'),
  );

  $form['role']['simple_ldap_role_basedn'] = array(
    '#type' => 'textfield',
    '#title' => t('Base DN'),
    '#default_value' => variable_get('simple_ldap_role_basedn', ''),
    '#required' => TRUE,
    '#description' => t('The Base DN that will be searched for roles.'),
  );

  $form['role']['simple_ldap_role_name'] = array(
    '#type' => 'textfield',
    '#title' => t('Role name attribute'),
    '#default_value' => variable_get('simple_ldap_role_name', 'cn'),
    '#required' => TRUE,
    '#description' => t('Which LDAP attribute should be mapped to a Drupal role name. This is commonly "cn".'),
  );

  $form['role']['simple_ldap_role_scope'] = array(
    '#type' => 'radios',
    '#title' => t('Search scope'),
    '#options' => array(
      'sub' => t('Subtree') . ' - ' . t('Search the base DN and all of its children for roles.'),
      'one' => t('One-level') . ' - ' . t('Do not include children of the base DN while searching for roles.'),
    ),
    '#required' => TRUE,
    '#default_value' => variable_get('simple_ldap_role_scope', 'sub'),
  );

/*
  $form['map'] = array(
    '#prefix' => '<div id="map">',
    '#suffix' => '</div>',
    '#tree' => TRUE,
    '#theme' => 'table',
    '#header' => array(t('Drupal'), t('LDAP')),
    '#rows' => array(),
  );

  for ($i = 0; $i < 10; $i++) {
    $d = array(
      '#id' => 'map' . $i . '-drupal',
      '#type' => 'textfield',
    );
    $l = array(
      '#id' => 'map' . $i . '-ldap',
      '#type' => 'textfield',
    );

    $form['map'][] = array (
      'drupal' => &$d,
      'ldap' => &$l,
    );

    $form['map']['#rows'][] = array(
      array('data' => &$d),
      array('data' => &$l),
    );

    unset($d);
    unset($l);
  }
*/

  return system_settings_form($form);
}
