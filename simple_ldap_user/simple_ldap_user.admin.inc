<?php
/**
 * @file
 * Functions for Simple LDAP User admin interface.
 */

/**
 * Simple LDAP User configuration form.
 */
function simple_ldap_user_admin() {
  $form = array();

  $form['user'] = array(
    '#type' => 'fieldset',
    '#title' => t('LDAP Users'),
  );

  $form['user']['simple_ldap_user_basedn'] = array(
    '#type' => 'textfield',
    '#title' => t('Base DN'),
    '#default_value' => variable_get('simple_ldap_user_basedn'),
    '#required' => TRUE,
    '#description' => t('The Base DN that will be searched for user accounts.'),
  );

  $form['user']['simple_ldap_user_scope'] = array(
    '#type' => 'radios',
    '#title' => t('Search scope'),
    '#options' => array(
      'sub' => t('Subtree') . ' - ' . t('Search the base DN and all of its children for user accounts.'),
      'one' => t('One-level') . ' - ' . t('Do not include children of the base DN while searching for user accounts.'),
    ),
    '#required' => TRUE,
    '#default_value' => variable_get('simple_ldap_user_scope', 'sub'),
  );

  $form['user']['simple_ldap_user_attribute_name'] = array(
    '#type' => 'textfield',
    '#title' => t('Username attribute'),
    '#default_value' => variable_get('simple_ldap_user_attribute_name', 'cn'),
    '#required' => TRUE,
    '#description' => t('Which LDAP attribute should be mapped to a Drupal username. This is commonly "cn" or "uid" for openLDAP, and "sAMAccountName" for Active Directory.'),
  );

  $form['user']['simple_ldap_user_attribute_mail'] = array(
    '#type' => 'textfield',
    '#title' => t('Email attribute'),
    '#default_value' => variable_get('simple_ldap_user_attribute_mail', 'mail'),
    '#required' => TRUE,
    '#description' => t("Which LDAP attribute should be mapped to a Drupal user's email address.") . ' ' . t('This is commonly "mail".'),
  );

  $form['user']['simple_ldap_user_attribute_pass'] = array(
    '#type' => 'textfield',
    '#title' => t('Password attribute'),
    '#default_value' => variable_get('simple_ldap_user_attribute_pass', 'userPassword'),
    '#required' => TRUE,
    '#description' => t("Which LDAP attribute should be mapped to a Drupal user's password.") . ' ' . t('This is commonly "userPassword".'),
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
