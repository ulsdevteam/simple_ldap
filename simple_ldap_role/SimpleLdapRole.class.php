<?php
/**
 * @file
 * Class defining a simple LDAP role.
 */

class SimpleLdapRole {

  // Variables exposed by __get() and __set()
  protected $attributes = array();
  protected $dn = FALSE;
  protected $exists = FALSE;
  protected $server = FALSE;

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
      strtolower(variable_get('simple_ldap_role_attribute_name')),
      strtolower(variable_get('simple_ldap_role_attribute_member')),
    );
    $attribute_map = simple_ldap_role_attribute_map();
    foreach ($attribute_map as $attribute) {
      if (isset($attribute['ldap'])) {
        $attributes[] = $attribute['ldap'];
      }
    }

    // Get the LDAP configuration.
    $base_dn = variable_get('simple_ldap_role_basedn');
    $scope = variable_get('simple_ldap_role_scope');
    $attribute_name = variable_get('simple_ldap_role_attribute_name');
    $filter = '(&(' . $attribute_name . '=' . $name . ')' . self::filter() . ')';

    // Attempt to load the role from the LDAP server.
    $result = $this->server->search($base_dn, $filter, $scope, $attributes, 0, 0);
    if ($result['count'] == 1) {
      $this->exists = TRUE;
      $this->dn = $result[0]['dn'];
      foreach ($attributes as $attribute) {
        if (isset($result[0][$attribute])) {
          $this->attributes[$attribute] = $result[0][$attribute];
        }
      }
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
        break;

      default:
        if (isset($this->attributes[$name])) {
          return $this->attributes[$name];
        }
        return array('count' => 0);
    }
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

      default:
        // Make sure $value is an array.
        if (!is_array($value)) {
          $value = array($value);
        }

        // Make sure $this->attributes[$name] exists.
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
   * Saves the object to the LDAP directory.
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
      unset($this->attributes[variable_get('simple_ldap_role_attribute_name')]);
      $result = $this->server->modify($this->dn, $this->attributes);
    }
    else {
      // Create a new entry.
      $this->attributes['objectclass'] = array(variable_get('simple_ldap_role_objectclass'));
      $result = $this->server->add($this->dn, $this->attributes);
    }

    // Success!
    if ($result !== FALSE) {
      $this->dirty = FALSE;
      return TRUE;
    }

    // Fail!
    return FALSE;
  }

  /**
   * Deletes the entry from the LDAP directory.
   */
  public function delete() {
    if ($this->exists) {
      $result = $this->server->delete($this->dn);
      if ($result) {
        $this->exists = FALSE;
        $this->dirty = FALSE;
        return TRUE;
      }
    }
    return FALSE;
  }

  protected static $roles = array();

  /**
   * Return a SimpleLdapRole object for the given role name.
   */
  public static function singleton($name) {
    if (!iset(self::$roles[$name])) {
      self::$roles[$name] = new SimpleLdapRole($name);
    }

    return self::$roles[$name];
  }

  /**
   * Return the LDAP search filter, as set by the module configuration.
   */
  public static function filter() {
    // Get the relevant configurations.
    $objectclass = variable_get('simple_ldap_role_objectclass', '*');
    $extrafilter = variable_get('simple_ldap_role_filter');

    // Construct the filter.
    $filter = '(objectclass=' . $objectclass . ')';
    if (!empty($extrafilter)) {
      $filter = '(&' . $filter . '(' . $extrafilter . '))';
    }

    return $filter;
  }

}
