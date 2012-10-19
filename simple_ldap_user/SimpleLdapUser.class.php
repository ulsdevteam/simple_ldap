<?php
/**
 * @file
 * Class defining a simple LDAP user.
 */

class SimpleLdapUser {

  // Variables exposed by __get() and __set()
  protected $dn = FALSE;
  protected $exists = FALSE;
  protected $attributes = array();

  // Internal variables.
  protected $server;
  protected $dirty = FALSE;

  /**
   * Constructor.
   */
  public function __construct($name) {
    // Load the LDAP server object.
    $this->server = SimpleLdapServer::singleton();

    // List of attributes to fetch from the LDAP server.
    $attributes = array(
      strtolower(variable_get('simple_ldap_user_attribute_name')),
      strtolower(variable_get('simple_ldap_user_attribute_mail')),
    );
    $map = simple_ldap_user_map();
    foreach ($map as $attribute) {
      if (isset($attribute['ldap'])) {
        $attributes[] = strtolower($attribute['ldap']);
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
        if (isset($result[0][$attribute]['count']) && $result[0][$attribute]['count'] > 0) {
          $this->attributes[$attribute] = $result[0][$attribute];
        }
      }
      $this->exists = TRUE;
    }
    else {
      $this->dn = $attribute_name . '=' . $name . ',' . $base_dn;
      $this->attributes[$attribute_name] = array($name);
    }
  }

  /**
   * Destructor.
   */
  public function __destruct() {
    if ($this->dirty && !$this->server->readonly) {
      if ($this->exists) {
        unset($this->attributes[variable_get('simple_ldap_user_attribute_name')]);
        $this->server->modify($this->dn, $this->attributes);
      }
      else {
        $this->attributes['objectclass'] = array(variable_get('simple_ldap_user_objectclass'));
        $result = $this->server->add($this->dn, $this->attributes);
      }
    }
  }

  /**
   * Magic __get() function.
   */
  public function __get($name) {
    switch ($name) {
      case 'attributes':
      case 'dn':
      case 'exists':
        return $this->$name;
      break;

      default:
        if (isset($this->attributes[$name])) {
          return $this->attributes[$name];
        }
    }

    return FALSE;
  }

  /**
   * Magic __set() function.
   */
  public function __set($name, $value) {
    switch ($name) {
      // Read-only values.
      case 'attributes':
      case 'dn':
      case 'exists':
        break;

      // Set attributes.
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

}
