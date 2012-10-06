<?php
/**
 * @file
 * Functions for Simple LDAP User admin interface.
 */

/**
 * Simple LDAP User configuration form.
 */
function simple_ldap_user_admin($form, &$form_state) {
  $form = array();

  // Initialize a Simple LDAP Server object. Used for dropdown options.
  $server = SimpleLdapServer::singleton();

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

  // Generate a list of object classes supported by the server.
  $objectclasses = $server->schema->get('objectclasses');
  foreach ($objectclasses as $key => $objectclass) {
    $objectclasses[$key] = $objectclass['name'];
  }
  asort($objectclasses);

  // Get the selected objectclass.
  $objectclass_selected = isset($form_state['values']['simple_ldap_user_objectclass']) ? $form_state['values']['simple_ldap_user_objectclass'] : variable_get('simple_ldap_user_objectclass', 'inetorgperson');

  $form['user']['simple_ldap_user_objectclass'] = array(
    '#type' => 'select',
    '#title' => t('User objectClass'),
    '#options' => $objectclasses,
    '#default_value' => $objectclass_selected,
    '#required' => TRUE,
    '#description' => t('Which LDAP objectClass should be used when searching for a user.'),
    '#ajax' => array(
      'callback' => 'simple_ldap_user_objectclass_ajax',
      'wrapper' => 'simple-ldap-user-attribute-name',
    ),
  );

  // Generate a list of attributes for the selected objectclass
  $result = $server->schema->attributes($objectclass_selected, TRUE);
  $attributes = array();
  foreach($result as $attribute) {
    $attributes[strtolower($attribute)] = $attribute;
  }
  asort($attributes);

  // Get the selected name attribute.
  $attribute_name_selected = isset($form_state['values']['simple_ldap_user_attribute_name']) ? $form_state['values']['simple_ldap_user_attribute_name'] : variable_get('simple_ldap_user_attribute_name', 'cn');

  $form['user']['simple_ldap_user_attribute_name'] = array(
    '#type' => 'select',
    '#title' => t('Username attribute'),
    '#prefix' => '<div id="simple-ldap-user-attribute-name">',
    '#suffix' => '</div>',
    '#options' => $attributes,
    '#default_value' => $attribute_name_selected,
    '#required' => TRUE,
    '#description' => t('Which LDAP attribute should be mapped to a Drupal username.') . ' ' .
                      t('This is commonly "cn" or "uid" for openLDAP, and "sAMAccountName" for Active Directory.'),
    '#ajax' => array(
      'callback' => 'simple_ldap_user_attribute_name_ajax',
      'wrapper' => 'simple-ldap-user-attribute-mail',
    ),
  );

  // Get the selected mail attribute.
  $attribute_mail_selected = isset($form_state['values']['simple_ldap_user_attribute_mail']) ? $form_state['values']['simple_ldap_user_attribute_mail'] : variable_get('simple_ldap_user_attribute_mail', 'mail');

  $form['user']['simple_ldap_user_attribute_mail'] = array(
    '#type' => 'select',
    '#title' => t('Email attribute'),
    '#prefix' => '<div id="simple-ldap-user-attribute-mail">',
    '#suffix' => '</div>',
    '#options' => $attributes,
    '#default_value' => $attribute_mail_selected,
    '#required' => TRUE,
    '#description' => t("Which LDAP attribute should be mapped to a Drupal user's email address.") . ' ' .
                      t('This is commonly "mail".'),
  );

  return system_settings_form($form);
}

function simple_ldap_user_objectclass_ajax($form, $form_state) {
  return $form['user']['simple_ldap_user_attribute_name'];
}
