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
  if (!simple_ldap_configured()) {
    drupal_set_message(t('Please configure the Simple LDAP server first.'), 'warning');
    return $form;
  }

  // Initialize a Simple LDAP Server object. Used for dropdown options.
  $server = SimpleLdapServer::singleton();

  // String to append to items disabled by $server->readonly.
  $readonly_note = $server->readonly ? ' (' . t('Disabled by LDAP Server configuration.') . ')' : '';

  $form['role'] = array(
    '#type' => 'fieldset',
    '#title' => t('LDAP Roles'),
  );

  $form['role']['simple_ldap_role_basedn'] = array(
    '#type' => 'textfield',
    '#title' => t('Base DN'),
    '#default_value' => variable_get('simple_ldap_role_basedn', $server->basedn),
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

  // Generate a list of attributes for the selected objectclass.
  $result = $server->schema->attributes($objectclass_selected, TRUE);
  $attributes = array();
  foreach ($result as $attribute) {
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
    '#description' => t('Which LDAP attribute should be mapped to a Drupal role name.') . ' ' . t('This is commonly "cn".'),
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
    '#description' => t('Which LDAP attribute defines the members of the role.') . ' ' . t('This is commonly "member".'),
    '#ajax' => array(
      'callback' => 'simple_ldap_role_attribute_member_ajax',
      'wrapper' => 'simple-ldap-role-attribute-member-default',
    ),
  );

  // Set default value if it exists in the list of attributes. If a default
  // value is not set, the empty option is selected.
  if (array_key_exists($attribute_member_selected, $attributes)) {
    $form['role']['simple_ldap_role_attribute_member']['#default_value'] = $attribute_member_selected;
  }

  $form['advanced'] = array(
    '#type' => 'fieldset',
    '#title' => t('Advanced'),
    '#collapsible' => TRUE,
    '#collapsed' => TRUE,
  );

  $form['advanced']['simple_ldap_role_filter'] = array(
    '#type' => 'textfield',
    '#title' => t('Search filter'),
    '#default_value' => variable_get('simple_ldap_role_filter'),
    '#description' => t('This filter will be combined with the normal search filter to find groups.') . ' ' . t('This can be used to require a certain attribute be present, for example.'),
  );

  $form['advanced']['simple_ldap_role_source'] = array(
    '#type' => 'radios',
    '#title' => t('Authoritative data source') . $readonly_note,
    '#options' => array(
      'ldap' => t('LDAP'),
      'drupal' => t('Drupal'),
    ),
    '#default_value' => simple_ldap_role_source(),
    '#disabled' => $server->readonly,
    '#description' => t('This determines the behavior of the data sync in the event of a conflict between LDAP and Drupal.'),
  );

  $form['advanced']['simple_ldap_role_sync'] = array(
    '#type' => 'radios',
    '#title' => t('Synchronization trigger'),
    '#options' => array(
      'hook_user_load' => t('Every time a user object is loaded from the database.') . ' (' . t('More real-time, best if there are frequent changes.') . ')',
      'hook_user_login' => t('Every time a user logs in.') . ' (' . t('Less LDAP traffic, best if changes are rare.') . ')',
    ),
    '#default_value' => variable_get('simple_ldap_role_sync', 'hook_user_load'),
  );

  $form['advanced']['simple_ldap_role_attribute_member_format'] = array(
    '#type' => 'radios',
    '#title' => t('Group member format'),
    '#options' => array(
      'dn' => t('DN'),
      'name' => t('Name'),
    ),
    '#default_value' => variable_get('simple_ldap_role_attribute_member_format', 'dn'),
  );

  $must = $server->schema->must($objectclass_selected, TRUE);
  $disabled = !in_array($attribute_member_selected, $must);
  $note = $disabled ? ' (' . t('@attribute is not a required attribute of @objectclass', array('@attribute' => $attributes[$attribute_member_selected], '@objectclass' => $objectclasses[$objectclass_selected])) . ')' : '';

  $form['advanced']['simple_ldap_role_attribute_member_default'] = array(
    '#type' => 'textfield',
    '#title' => t('Default group member') . $note . $readonly_note,
    '#default_value' => variable_get('simple_ldap_role_attribute_member_default'),
    '#disabled' => $disabled || $server->readonly,
    '#description' => t('If the selected member attribute is a required attribute of the selected objectclass, then every LDAP group must have at least one member.') . ' ' . t('The value here will be used as that default member in the event that the group would otherwise be empty.') . ' ' . t('Leave this blank if the group should be deleted instead.'),
    '#prefix' => '<div id="simple-ldap-role-attribute-member-default">',
    '#suffix' => '</div>',
  );

  return system_settings_form($form);
}

/**
 * Handle simple_ldap_role_objectclass ajax calls.
 */
function simple_ldap_role_objectclass_ajax($form, $form_state) {
  return array(
    $form['role']['simple_ldap_role_attribute_name'],
    $form['role']['simple_ldap_role_attribute_member'],
  );
}

/**
 * Handle simple_ldap_role_attribute_member ajax calls.
 */
function simple_ldap_role_attribute_member_ajax($form, $form_state) {
  return array(
    $form['advanced']['simple_ldap_role_attribute_member_default'],
  );
}
