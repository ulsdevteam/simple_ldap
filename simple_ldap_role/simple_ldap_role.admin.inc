<?php
/**
 * @file
 * Functions for Simple LDAP Role admin interface.
 */

/**
 * Simple LDAP Role configuration form.
 */
function simple_ldap_role_admin($form, &$form_state) {
  $form = array();

  // Verify that simple_ldap_user has been configured.
  if (!simple_ldap_user_configured()) {
    drupal_set_message(t('Please configure Simple LDAP Users first.'), 'warning');
    return $form;
  }

  // Initialize a Simple LDAP Server object. Used for dropdown options.
  $server = SimpleLdapServer::singleton();

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

  // Generate a list of object classes supported by the server.
  $objectclasses = $server->schema->get('objectclasses');
  foreach ($objectclasses as $key => $objectclass) {
    $objectclasses[$key] = $objectclass['name'];
  }
  asort($objectclasses);

  // Get the selected objectclass.
  $objectclass_selected = isset($form_state['values']['simple_ldap_role_objectclass']) ? $form_state['values']['simple_ldap_role_objectclass'] : variable_get('simple_ldap_role_objectclass', 'groupofnames');

  $form['role']['simple_ldap_role_objectclass'] = array(
    '#type' => 'select',
    '#title' => t('Role objectClass'),
    '#options' => $objectclasses,
    '#default_value' => $objectclass_selected,
    '#required' => TRUE,
    '#description' => t('Which LDAP objectClass should be used when searching for a role.'),
    '#ajax' => array(
      'callback' => 'simple_ldap_role_objectclass_ajax',
      'wrapper' => 'simple-ldap-role-attributes',
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
  $attribute_name_selected = isset($form_state['values']['simple_ldap_role_attribute_name']) ? $form_state['values']['simple_ldap_role_attribute_name'] : variable_get('simple_ldap_role_attribute_name', 'cn');


  $form['role']['simple_ldap_role_attribute_name'] = array(
    '#type' => 'select',
    '#title' => t('Role name attribute'),
    '#prefix' => '<div id="simple-ldap-role-attributes">',
    '#options' => $attributes,
    '#required' => TRUE,
    '#description' => t('Which LDAP attribute should be mapped to a Drupal role name.') . ' ' .
                      t('This is commonly "cn".'),
  );

  // Set default value if it exists in the list of attributes. If a default
  // value is not set, the empty option is selected.
  if (array_key_exists($attribute_name_selected, $attributes)) {
    $form['role']['simple_ldap_role_attribute_name']['#default_value'] = $attribute_name_selected;
  }

  // Get the selected member attribute.
  $attribute_member_selected = isset($form_state['values']['simple_ldap_role_attribute_member']) ? $form_state['values']['simple_ldap_role_attribute_member'] : variable_get('simple_ldap_role_attribute_member', 'member');

  $form['role']['simple_ldap_role_attribute_member'] = array(
    '#type' => 'select',
    '#title' => t('Role member attribute'),
    '#suffix' => '</div>',
    '#options' => $attributes,
    '#required' => TRUE,
    '#description' => t('Which LDAP attribute defines the members of the role.') . ' ' .
                      t('This is commonly "member".'),
  );

  // Set default value if it exists in the list of attributes. If a default
  // value is not set, the empty option is selected.
  if (array_key_exists($attribute_member_selected, $attributes)) {
    $form['role']['simple_ldap_role_attribute_member']['#default_value'] = $attribute_member_selected;
  }

  return system_settings_form($form);
}

function simple_ldap_role_objectclass_ajax($form, $form_state) {
  return array($form['role']['simple_ldap_role_attribute_name'], $form['role']['simple_ldap_role_attribute_member']);
}
