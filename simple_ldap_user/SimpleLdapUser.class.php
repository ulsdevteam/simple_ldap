<?php
/**
 * @file
 * Class defining a simple LDAP user.
 */

class SimpleLdapUser {

  public $dn;
  public $attributes;

  private static $users;

  /**
   * Constructor.
   */
  function __construct($dn) {
    $this->dn = $dn;
  }

  /**
   * Sets the object properties to read-only.
   */
  public function __set($name, $value) { }

  /**
   * Searches for an LDAP entry, and returns a SimpleLdapUser object if found.
   */
  public static function load($name) {
    if (!isset(self::$users)) {
      self::$users = array();
    }

    if (!isset(self::$users[$name])) {
      // Load the user if it exists.
      $dn = self::dn($name);
      if ($dn === FALSE) {
        self::$users[$name] = FALSE;
      }
      else {
        self::$users[$name] = new SimpleLdapUser($dn);
      }
    }

    return self::$users[$name];
  }

  /**
   * Checks for the existance of an LDAP user entry matching the given name.
   */
  public static function exists($name) {
    $ldap_user = self::_search($name);
    return (boolean) $ldap_user;
  }

  /**
   * Fetches the DN for the given user name.
   */
  public static function dn($name) {
    $ldap_user = self::_search($name);
    if ($ldap_user === FALSE || $ldap_user['count'] == 0) {
      return FALSE;
    }
    return $ldap_user[0]['dn'];
  }

  /**
   * Internal search helper function.
   */
  protected static function _search($name) {
    // Load the LDAP server object.
    $server = SimpleLdapServer::singleton();

    // Get the LDAP configuration.
    $base_dn = variable_get('simple_ldap_user_basedn');
    $scope = variable_get('simple_ldap_user_scope');
    $search = strtolower(variable_get('simple_ldap_user_attribute_name'));
    $filter = '(' . $search . '=' . $name . ')';

    // Search for the entry.
    return $server->search($base_dn, $filter, $scope, array('dn'), 1, 1);
  }

}
