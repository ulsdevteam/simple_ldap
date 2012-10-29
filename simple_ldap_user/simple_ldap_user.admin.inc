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

  // Verify that simple_ldap has been configured.
  if (!simple_ldap_configured()) {
    drupal_set_message(t('Please configure the Simple LDAP server first.'), 'warning');
    return $form;
  }

  // Initialize a Simple LDAP Server object. Used for dropdown options.
  $server = SimpleLdapServer::singleton();

  // String to append to items disabled by $server->readonly.
  $disabled_note = $server->readonly ? ' (' . t('Disabled by LDAP Server configuration.') . ')' : '';

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
      'wrapper' => 'simple-ldap-user-attributes',
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
  $attribute_name_selected = isset($form_state['values']['simple_ldap_user_attribute_name']) ? $form_state['values']['simple_ldap_user_attribute_name'] : variable_get('simple_ldap_user_attribute_name', 'cn');

  // Additional description if !$server->readonly.
  $description = $server->readonly ? '' : ' ' . t('This attribute is also used as the RDN when provisioning user accounts to LDAP.');

  $form['user']['simple_ldap_user_attribute_name'] = array(
    '#type' => 'select',
    '#title' => t('Username attribute'),
    '#prefix' => '<div id="simple-ldap-user-attributes">',
    '#options' => $attributes,
    '#required' => TRUE,
    '#description' => t('Which LDAP attribute should be mapped to a Drupal username.') . ' ' . t('This is commonly "cn" or "uid" for openLDAP, and "sAMAccountName" for Active Directory.') . $description,
  );

  // Set default value if it exists in the list of attributes. If a default
  // value is not set, the empty option is selected.
  if (array_key_exists($attribute_name_selected, $attributes)) {
    $form['user']['simple_ldap_user_attribute_name']['#default_value'] = $attribute_name_selected;
  }

  // Get the selected mail attribute.
  $attribute_mail_selected = isset($form_state['values']['simple_ldap_user_attribute_mail']) ? $form_state['values']['simple_ldap_user_attribute_mail'] : variable_get('simple_ldap_user_attribute_mail', 'mail');

  $form['user']['simple_ldap_user_attribute_mail'] = array(
    '#type' => 'select',
    '#title' => t('Email attribute'),
    '#options' => $attributes,
    '#required' => TRUE,
    '#description' => t("Which LDAP attribute should be mapped to a Drupal user's email address.") . ' ' . t('This is commonly "mail".'),
  );

  // Set default value if it exists in the list of attributes. If a default
  // value is not set, the empty option is selected.
  if (array_key_exists($attribute_mail_selected, $attributes)) {
    $form['user']['simple_ldap_user_attribute_mail']['#default_value'] = $attribute_mail_selected;
  }

  // Get the selected password attribute.
  $attribute_pass_selected = isset($form_state['values']['simple_ldap_user_attribute_pass']) ? $form_state['values']['simple_ldap_user_attribute_pass'] : variable_get('simple_ldap_user_attribute_pass', 'userpassword');

  $form['user']['simple_ldap_user_attribute_pass'] = array(
    '#type' => 'select',
    '#title' => t('Password attribute') . $disabled_note,
    '#suffix' => '</div>',
    '#options' => $attributes,
    '#description' => t("Which LDAP attribute should be mapped to a Drupal user's password.") . ' ' . t('This is only used for password resets, not for authentication, and is commonly "userPassword".'),
    '#disabled' => $server->readonly,
    '#empty_value' => FALSE,
  );

  // Set default value if it exists in the list of attributes. If a default
  // value is not set, the empty option is selected.
  if (array_key_exists($attribute_pass_selected, $attributes)) {
    $form['user']['simple_ldap_user_attribute_pass']['#default_value'] = $attribute_pass_selected;
  }

  $form['user']['simple_ldap_user_password_hash'] = array(
    '#type' => 'select',
    '#title' => t('Password hashing algorithm') . $disabled_note,
    '#options' => simple_ldap_user_hash_types(),
    '#description' => t('Which encryption algorithm should be used to encrypt passwords when writing to LDAP.') . ' ' . t('Note that mhash support is required for SMD5, SHA, and SSHA.'),
    '#disabled' => $server->readonly,
    '#default_value' => variable_get('simple_ldap_user_password_hash', 'salted sha'),
    '#empty_value' => 'none',
  );

  $form['advanced'] = array(
    '#type' => 'fieldset',
    '#title' => t('Advanced'),
    '#collapsible' => TRUE,
    '#collapsed' => TRUE,
  );

  $form['advanced']['simple_ldap_user_filter'] = array(
    '#type' => 'textfield',
    '#title' => t('Search filter'),
    '#default_value' => variable_get('simple_ldap_user_filter'),
    '#description' => t('This filter will be combined with the normal search filter to find users.') . ' ' . t('This can be used to require a certain attribute be present, for example.'),
  );

  $form['advanced']['simple_ldap_user_source'] = array(
    '#type' => 'radios',
    '#title' => t('Authoratative data source') . $disabled_note,
    '#options' => array(
      'ldap' => t('LDAP'),
      'drupal' => t('Drupal'),
    ),
    '#default_value' => simple_ldap_user_source(),
    '#disabled' => $server->readonly,
    '#description' => t('This determines the behavior of the data sync in the event of a conflict between LDAP and Drupal.') . ' ' . t('Note, that if the LDAP server is set as read-only, LDAP is always considered to be the authoratative data source.'),
  );

  $form['advanced']['simple_ldap_user_sync'] = array(
    '#type' => 'radios',
    '#title' => t('Synchronization trigger'),
    '#options' => array(
      'hook_user_load' => t('Every time a user object is loaded from the database.') . ' (' . t('More real-time, best if there are frequent changes.') . ')',
      'hook_user_login' => t('Every time a user logs in.') . ' (' . t('Less LDAP traffic, best if changes are rare.') . ')',
    ),
    '#default_value' => variable_get('simple_ldap_user_sync', 'hook_user_load'),
  );

  $form['advanced']['simple_ldap_user_delete'] = array(
    '#type' => 'checkbox',
    '#title' => t('Allow Drupal to delete LDAP users.') . $disabled_note,
    '#default_value' => variable_get('simple_ldap_user_delete', TRUE),
    '#disabled' => $server->readonly,
    '#description' => t('Disable this to protect LDAP users from being deleted by Drupal, while still allowing other LDAP write operations.'),
  );

  // Generate a table to display the attribute map if one is configured.
  $table = '';
  $map = simple_ldap_user_map();
  if (!empty($map)) {
    $table = '<table>';
    $table .= '<thead><tr><th>' . t('Drupal field') . '</th><th>' . t('LDAP attribute') . '</th></tr></thead>';
    $table .= '<tbody>';
    $class = 'odd';
    foreach ($map as $item) {
      $table .= '<tr class="' . $class . '">';
      $table .= '<td>' . $item['drupal'] . '</td>';
      $table .= '<td>' . $item['ldap'] . '</td>';
      $table .= '</tr>';
      $class = $class == 'odd' ? 'even' : 'odd';
    }
    $table .= '</tbody></table>';
  }

  $form['advanced']['simple_ldap_user_map'] = array(
    '#type' => 'item',
    '#title' => t('Attribute map'),
    '#description' => $table . t('Additional attribute maps can be specified in settings.php.') . ' ' . t('The format of how this should be set is shown below.') . "<pre>\$conf['simple_ldap_user_map'] = array(\n  // Generic example.\n  array(\n    'type' => 'field',\n    'drupal' => 'drupal-user-field-machine-name',\n    'ldap' => 'ldap-attribute',\n  ),\n  // First name example.\n  array(\n    'type' => 'field',\n    'drupal' => 'field_first_name',\n    'ldap' => 'givenName',\n  ),\n  // Last name example.\n  array(\n    'type' => 'field',\n    'drupal' => 'field_last_name',\n    'ldap' => 'sn',\n  ),\n;</pre>",
  );

  return system_settings_form($form);
}

/**
 * Handle simple_ldap_user_objectclass ajax calls.
 */
function simple_ldap_user_objectclass_ajax($form, $form_state) {
  return array(
    $form['user']['simple_ldap_user_attribute_name'],
    $form['user']['simple_ldap_user_attribute_mail'],
    $form['user']['simple_ldap_user_attribute_pass'],
  );
}
