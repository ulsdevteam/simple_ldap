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
  public function __construct($dn) {
    $this->dn = $dn;
    $this->attributes = array();

    // List of attributes to fetch.
    $attributes = array(
      variable_get('simple_ldap_user_attribute_name'),
      variable_get('simple_ldap_user_attribute_mail'),
    );

    // Load attributes from directory.
    $server = SimpleLdapServer::singleton();
    $entry = $server->search($this->dn, 'objectClass=*', 'base', $attributes);

    // Parse entry and extract attributes.
    if ($entry !== FALSE && $entry['count'] > 0) {
      for ($i = 0; $i < $entry[0]['count']; $i++) {
        for ($j = 0; $j < $entry[0][$entry[0][$i]]['count']; $j++) {
          $this->attributes[$entry[0][$i]][] = $entry[0][$entry[0][$i]][$j];
        }
      }
    }
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
    return (boolean) $ldap_user;
  }

  /**
   * Fetches the DN for the given user name.
   */
  public static function dn($name) {
    $ldap_user = self::doSearch($name);
    if ($ldap_user === FALSE || $ldap_user['count'] == 0) {
      return FALSE;
    }
    return $ldap_user[0]['dn'];
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
    return $server->search($base_dn, $filter, $scope, array('dn'), 1, 1);
  }

}
