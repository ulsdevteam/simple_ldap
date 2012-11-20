<?php
/**
 * @file
 * Class defining a simple LDAP user.
 */

class SimpleLdapUser {

  // Variables exposed by __get() and __set()
  protected $attributes = array();
  protected $dn = FALSE;
  protected $exists = FALSE;
  protected $server;

  // Internal variables.
  protected $dirty = FALSE;

  /**
   * Constructor.
   */
  public function __construct($name) {
    // Load the LDAP server object.
    $this->server = SimpleLdapServer::singleton();

    // List of attributes to fetch from the LDAP server.
    $attributes = array(
      drupal_strtolower(variable_get('simple_ldap_user_attribute_name', 'cn')),
      drupal_strtolower(variable_get('simple_ldap_user_attribute_mail', 'mail')),
    );
    $map = simple_ldap_user_map();
    foreach ($map as $attribute) {
      if (isset($attribute['ldap'])) {
        $attributes[] = $attribute['ldap'];
      }
    }

    // Get the LDAP configuration.
    $base_dn = variable_get('simple_ldap_user_basedn');
    $scope = variable_get('simple_ldap_user_scope');
    $attribute_name = variable_get('simple_ldap_user_attribute_name');
    $filter = '(&(' . $attribute_name . '=' . $name . ')' . self::filter() . ')';

    // Attempt to load the user from the LDAP server.
    $result = $this->server->search($base_dn, $filter, $scope, $attributes, 0, 1);
    if ($result['count'] == 1) {
      $this->dn = $result[0]['dn'];
      foreach ($attributes as $attribute) {
        if (isset($result[0][$attribute])) {
          $this->attributes[$attribute] = $result[0][$attribute];
        }
      }
      $this->exists = TRUE;
    }
    else {
      $this->dn = $attribute_name . '=' . $name . ',' . $base_dn;
      $this->attributes[$attribute_name] = array('count' => 1, 0 => $name);
    }
  }

  /**
   * Destructor.
   */
  public function __destruct() {
    $this->save();
  }

  /**
   * Magic __get() function.
   */
  public function __get($name) {
    switch ($name) {
      case 'attributes':
      case 'dn':
      case 'exists':
      case 'server':
        return $this->$name;

      default:
        if (isset($this->attributes[$name])) {

          // Make sure 'count' is set.
          if (!isset($this->attributes[$name]['count'])) {
            $this->attributes[$name]['count'] = count($this->attributes[$name]);
          }

          return $this->attributes[$name];
        }
        return array('count' => 0);
    }
  }

  /**
   * Magic __set() function.
   */
  public function __set($name, $value) {
    $attribute_pass = variable_get('simple_ldap_user_attribute_pass');

    switch ($name) {
      // Read-only values.
      case 'attributes':
      case 'dn':
      case 'exists':
        break;

      // Look up the raw password from the internal reverse hash map. This
      // intentionally falls through to default:.
      case $attribute_pass:
        if (isset(self::$hash[$value])) {
          $value = simple_ldap_user_hash(self::$hash[$value]);
        }
        else {
          // A plain text copy of the password is not available. Do not
          // overwrite the existing value.
          return;
        }

      default:
        // Make sure $value is an array.
        if (!is_array($value)) {
          $value = array($value);
        }

        // Make sure $this->attributes[$name] is an array.
        if (!isset($this->attributes[$name])) {
          $this->attributes[$name] = array();
        }

        // Compare the current value with the given value.
        $diff1 = @array_diff($this->attributes[$name], $value);
        $diff2 = @array_diff($value, $this->attributes[$name]);

        // If there are any differences, update the current value.
        if (!empty($diff1) || !empty($diff2)) {
          $this->attributes[$name] = $value;
          $this->dirty = TRUE;
        }

    }

  }

  /**
   * Authenticates this user with the given password.
   */
  public function authenticate($password) {
    if ($this->exists) {
      $auth = $this->server->bind($this->dn, $password);
      return $auth;
    }
    return FALSE;
  }

  /**
   * Save user to LDAP.
   *
   * @return boolean
   *   TRUE on success, FALSE on failure.
   */
  public function save() {
    // If there is nothing to save, return "success".
    if (!$this->dirty) {
      return TRUE;
    }

    // If the server is set to readonly, return "fail".
    if ($this->server->readonly) {
      return FALSE;
    }

    if ($this->exists) {
      // Update existing entry.
      unset($this->attributes[variable_get('simple_ldap_user_attribute_name')]);
      $result = $this->server->modify($this->dn, $this->attributes);
    }
    else {
      // Create new entry.
      $this->attributes['objectclass'] = array(variable_get('simple_ldap_user_objectclass'));
      $result = $this->server->add($this->dn, $this->attributes);
    }

    // Successfully saved.
    if ($result !== FALSE) {
      $this->dirty = FALSE;
      return TRUE;
    }

    // Default to "fail".
    return FALSE;
  }

  /**
   * Delete user from LDAP directory.
   *
   * @return boolean
   *   TRUE on success, FALSE on failure.
   */
  public function delete() {
    if ($this->exists && variable_get('simple_ldap_user_delete', TRUE)) {
      $result = $this->server->delete($this->dn);
      if ($result) {
        $this->exists = FALSE;
        $this->dirty = FALSE;
        return TRUE;
      }
    }

    return FALSE;
  }

  /**
   * Return the LDAP search filter, as set by the module configuration.
   */
  public static function filter() {
    // Get the relevant configurations.
    $objectclass = variable_get('simple_ldap_user_objectclass', '*');
    $extrafilter = variable_get('simple_ldap_user_filter');

    // Construct the filter.
    $filter = '(objectclass=' . $objectclass . ')';
    if (!empty($extrafilter)) {
      $filter = '(&' . $filter . '(' . $extrafilter . '))';
    }

    return $filter;
  }

  protected static $users = array();

  // This is intentionally private because it handles sensitive information.
  private static $hash = array();

  /**
   * Return a SimpleLdapUser object for the given username.
   */
  public static function singleton($name) {
    if (!isset(self::$users[$name])) {
      self::$users[$name] = new SimpleLdapUser($name);
    }

    return self::$users[$name];
  }

  /**
   * Clear the cache for the given username.
   */
  public static function reset($name = NULL) {
    if ($name === NULL) {
      self::$users = array();
    }
    else {
      unset(self::$users[$name]);
    }
  }

  /**
   * Internal password hash storage.
   *
   * This is called by the customized user_hash_password() function in
   * simple_ldap_user.password.inc to create an internal reverse hash lookup, so
   * passwords can be updated in LDAP. The hash is not exposed by the class API,
   * and is cleared after every page load.
   */
  public static function hash($key, $value) {
    self::$hash[$key] = $value;
  }

}
