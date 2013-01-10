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
   *
   * @param string $name
   *   The drupal user name to search for, and load from LDAP.
   *
   * @throw SimpleLdapException
   */
  public function __construct($name) {
    // Load the LDAP server object.
    $this->server = SimpleLdapServer::singleton();

    // List of attributes to fetch from the LDAP server.
    $attributes = array(
      drupal_strtolower(variable_get('simple_ldap_user_attribute_name', 'cn')),
      drupal_strtolower(variable_get('simple_ldap_user_attribute_mail', 'mail')),
    );
    $attribute_map = simple_ldap_user_attribute_map();
    foreach ($attribute_map as $attribute) {
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
   * Magic __get() function.
   *
   * @param string $name
   *   Name of the variable to get.
   *
   * @return mixed
   *   Returns the value of the requested variable, if allowed.
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
   *
   * @param string $name
   *   The name of the attribute to set.
   * @param mixed $value
   *   The value to assigned to the given attribute.
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
          $value = SimpleLdap::hash(self::$hash[$value]);
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
   *
   * @param string $password
   *   The password to use for authentication.
   *
   * @return boolean
   *   TRUE on success, FALSE on failure
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
   *   TRUE on success.
   *
   * @throw SimpleLdapException
   */
  public function save() {
    // If there is nothing to save, return "success".
    if (!$this->dirty) {
      return TRUE;
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

    // No exceptions were thrown, so the save was successful.
    $this->dirty = FALSE;
    return TRUE;
  }

  /**
   * Delete user from LDAP directory.
   *
   * @return boolean
   *   TRUE on success.
   *
   * @throw SimpleLdapException
   */
  public function delete() {
    if (variable_get('simple_ldap_user_delete', TRUE)) {
      $this->server->delete($this->dn);
      $this->exists = FALSE;
      $this->dirty = FALSE;
      return TRUE;
    }

    throw new SimpleLdapException('Simple LDAP User configuration does not allow users to be delete from LDAP.');
  }

  /**
   * Return the LDAP search filter, as set by the module configuration.
   *
   * @return string
   *   The LDAP search filter to satisfy the module configuration options.
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

  /**
   * Return a SimpleLdapUser object for the given username.
   *
   * @param string $name
   *   The drupal user name to search for, and load from LDAP.
   * @param boolean $reset
   *   If TRUE, the cache for the specified user is cleared, and the user is
   *   reloaded from LDAP.
   *
   * @return object
   *   SimpleLdapUser
   *
   * @throw SimpleLdapException
   */
  public static function singleton($name, $reset = FALSE) {
    if ($reset || !isset(self::$users[$name])) {
      self::$users[$name] = new SimpleLdapUser($name);
    }

    return self::$users[$name];
  }

  /**
   * Clear the cache for the given username.
   *
   * @param string $name
   *   If specified, clear the cache entry for the given user. If not
   *   specified, all cache entries are cleared.
   */
  public static function reset($name = NULL) {
    if ($name === NULL) {
      self::$users = array();
    }
    else {
      unset(self::$users[$name]);
    }
  }

  // This is intentionally private because it handles sensitive information.
  private static $hash = array();

  /**
   * Internal password hash storage.
   *
   * This is called by the customized user_hash_password() function in
   * simple_ldap_user.password.inc to create an internal reverse hash lookup, so
   * passwords can be updated in LDAP. The hash is not exposed by the class API,
   * and is cleared after every page load.
   *
   * @param string $key
   *   The hash key
   * @param string $value
   *   The hash value
   */
  public static function hash($key, $value) {
    self::$hash[$key] = $value;
  }

}
