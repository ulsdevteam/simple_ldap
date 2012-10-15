<?php
/**
 * @file
 * Class defining a simple LDAP user.
 *
 * @todo cache user lookups. singleton($name), maybe?
 */

class SimpleLdapUser {

  // Variables exposed by __get() and __set()
  protected $dn = FALSE;
  protected $attributes = array();

  // Internal variables
  protected $server;
  protected $dirty = FALSE;

  /**
   * Constructor.
   */
  public function __construct($name) {
    // Load the LDAP server object.
    $this->server = SimpleLdapServer::singleton();

    // List of attributes to fetch from the server.
    $attributes = array(
      variable_get('simple_ldap_user_attribute_name'),
      variable_get('simple_ldap_user_attribute_mail'),
    );

    // Get the LDAP configuration.
    $base_dn = variable_get('simple_ldap_user_basedn');
    $scope = variable_get('simple_ldap_user_scope');
    $search = variable_get('simple_ldap_user_attribute_name');
    $filter = '(&(' . $search . '=' . $name . ')' . self::filter() . ')';

    // Attempt to load the user from the LDAP server.
    $result = $this->server->search($base_dn, $filter, $scope, $attributes, 0, 1);
    if ($result['count'] == 1) {
      $this->dn = $result[0]['dn'];
      foreach ($attributes as $attribute) {
        if (isset($result[0][$attribute]['count']) && $result[0][$attribute]['count'] > 0) {
          $this->attributes[$attribute] = $result[0][$attribute][0];
        }
      }
    }
  }

  /**
   * Destructor.
   *
   * @todo Save any changes back to LDAP if !$this->server->readonly.
   */
  public function __destruct() {
  }

  /**
   * Magic __get() function.
   */
  public function __get($name) {
    switch ($name) {
      case 'attributes':
      case 'dn':
        return $this->$name;
      break;

      default:
        if (isset($this->attributes[$name])) {
          return $this->attributes[$name];
        }
      break;
    }

    return FALSE;
  }

  /**
   * Magic __set() function.
   *
   * @todo __set() only if !$this->server->readonly
   */
  public function __set($name, $value) {
  }

  /**
   * Returns whether this user exists in LDAP.
   */
  public function exists() {
    return (boolean) $this->dn;
  }

  /**
   * Authenticates this user with the given password.
   */
  public function authenticate($password) {
    if ($this->exists()) {
      $auth = $this->server->bind($this->dn, $password);
      return $auth;
    }
    return FALSE;
  }

  /**
   * Return the LDAP search filter, as set by the module configuration.
   */
  public static function filter() {
    static $filter;

    if (!isset($filter)) {
      // Get the relevant configurations.
      $objectclass = variable_get('simple_ldap_user_objectclass', '*');
      $extrafilter = variable_get('simple_ldap_user_filter');

      // Construct the filter.
      $filter = '(objectclass=' . $objectclass . ')';
      if ($extrafilter !== NULL) {
        $filter = '(&' . $filter . '(' . $extrafilter . '))';
      }
    }

    return $filter;
  }

}
