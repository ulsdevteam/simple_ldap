<?php
/**
 * @file
 * Class defining a simple LDAP user.
 */

class SimpleLdapUser {

  public $dn;
  public $attributes;
  protected $server;

  private static $users;

  /**
   * Constructor.
   */
  public function __construct($dn) {
    $this->dn = $dn;
    $this->attributes = array();

    // List of attributes to fetch.
    $attributes = array(
      variable_get('simple_ldap_user_attribute_name'),
      variable_get('simple_ldap_user_attribute_mail'),
    );

    // Load attributes from directory.
    $this->server = SimpleLdapServer::singleton();
    $entry = $this->server->entry($this->dn);
    $this->attributes = $entry[$this->dn];

  }

  /**
   * Sets the object properties to read-only.
   */
  public function __set($name, $value) {
  }

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
    $ldap_user = self::doSearch($name);
    if ($ldap_user === FALSE || count($ldap_user) == 0) {
      return FALSE;
    }
    return TRUE;
  }

  /**
   * Fetches the DN for the given user name.
   */
  public static function dn($name) {
    $ldap_user = self::doSearch($name);
    if ($ldap_user === FALSE || count($ldap_user) == 0) {
      return FALSE;
    }
    return $ldap_user[0];
  }

  /**
   * Authenticates the user with the given password.
   */
  public function authenticate($password) {
    $auth = $this->server->bind($this->dn, $password);
    return $auth;
  }

  /**
   * Internal search helper function.
   */
  protected static function doSearch($name) {
    // Load the LDAP server object.
    $server = SimpleLdapServer::singleton();

    // Get the LDAP configuration.
    $base_dn = variable_get('simple_ldap_user_basedn');
    $scope = variable_get('simple_ldap_user_scope');
    $search = strtolower(variable_get('simple_ldap_user_attribute_name'));
    $filter = '(' . $search . '=' . $name . ')';

    // Search for the entry.
    return array_keys($server->search($base_dn, $filter, $scope, array('dn'), 1, 1));
  }

}
