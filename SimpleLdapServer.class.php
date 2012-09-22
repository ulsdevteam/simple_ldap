<?php
/**
 * @file
 * Class to handle LDAP server connections and related operations.
 */

/**
 * Simple LDAP server class.
 */
class SimpleLdapServer {

  // Singleton instance.
  private static $instance;

  // LDAP connection parameters.
  protected $hostname;
  protected $port;
  protected $encryption;

  // LDAP directory parameters.
  protected $binddn;
  protected $bindpw;

  // LDAP resource link.
  protected $resource = FALSE;
  protected $bound = FALSE;

  /**
   * Constructor.
   *
   * This constructor builds the object by pulling the configuration parameters
   * from the Drupal variable system.
   */
  public function __construct() {
    // Assume LDAPv3.
    ldap_set_option($this->resource, LDAP_OPT_PROTOCOL_VERSION, 3);

    $this->hostname = variable_get('simple_ldap_hostname');
    $this->port = variable_get('simple_ldap_port', '389');
    $this->encryption = variable_get('simple_ldap_encryption', 'none');
    $this->binddn = variable_get('simple_ldap_binddn');
    $this->bindpw = variable_get('simple_ldap_bindpw');
    $this->bind();
  }

  /**
   * Destructor.
   */
  public function __destruct() {
    $this->unbind();
  }

  /**
   * Magic __set() function, handles changing server settings.
   */
  public function __set($name, $value) {
    switch ($name) {
      case 'hostname':
      case 'port':
      case 'encryption':
        $this->disconnect();
      case 'binddn':
      case 'bindpw':
        $this->unbind();
        $this->$name = $value;
        break;

      default:
    }
  }

  /**
   * Singleton constructor.
   */
  public static function singleton($reset = FALSE) {
    if ($reset || !isset(self::$instance)) {
      self::$instance = new SimpleLdapServer();
    }
    return self::$instance;
  }

  /**
   * Connect to the LDAP server.
   *
   * @return boolean
   *   TRUE on success, FALSE on failure.
   */
  protected function connect() {
    if (!$this->resource) {
      $url = $this->encryption == 'ssl' ? 'ldaps://' . $this->hostname : $this->hostname;
      $this->resource = ldap_connect($url, $this->port);
      if ($this->resource === FALSE) {
        return FALSE;
      }
    }

    return TRUE;
  }

  /**
   * Unbind and disconnect from the LDAP server.
   *
   * @return boolean
   *   TRUE on success, FALSE on failure.
   */
  protected function disconnect() {
    if ($this->unbind()) {
      $this->resource = FALSE;
      return TRUE;
    }
    return FALSE;
  }

  /**
   * Connect and bind to the LDAP server.
   *
   * @return boolean
   *   TRUE on success, FALSE on failure.
   */
  protected function bind() {
    // Connect first.
    if ($this->connect() === FALSE) {
      return FALSE;
    }

    if (!$this->bound) {
      // Start TLS on the LDAP connection.
      if ($this->encryption == 'tls') {
        ldap_start_tls($this->resource);
      }

      // Bind to the LDAP server.
      $this->bound = ldap_bind($this->resource, $this->binddn, $this->bindpw);
    }

    return $this->bound;
  }

  /**
   * Unbind from the LDAP server.
   *
   * @return boolean
   *   TRUE on success, FALSE on failure.
   */
  protected function unbind() {
    if ($this->bound) {
      $this->bound = !ldap_unbind($this->resource);
    }
    return !$this->bound;
  }

  /**
   * Search the LDAP server.
   */
  public function search($base_dn, $filter, $scope = 'sub', $attributes = array(), $attrsonly = 0, $sizelimit = 0, $timelimit = 0, $deref = LDAP_DEREF_NEVER) {
    // Make sure there is a valid binding.
    if (!$this->bind()) {
      return FALSE;
    }

    // Perform the search based on the scope provided.
    switch ($scope) {
      case 'one':
        $result = ldap_list($this->resource, $base_dn, $filter, $attributes, $attrsonly, $sizelimit, $timelimit, $deref);
        break;

      case 'sub':
      default:
        $result = ldap_search($this->resource, $base_dn, $filter, $attributes, $attrsonly, $sizelimit, $timelimit, $deref);
        break;
    }

    // Error handler.
    if ($result === FALSE) {
      return FALSE;
    }

    $entries = ldap_get_entries($this->resource, $result);
    return $entries;
  }

  /**
   * Authenticate an arbitrary DN and password.
   *
   * This does a simple bind/unbind, simply to test whether the credentials are
   * valid.
   */
  public function authenticate($binddn, $bindpw) {
    $url = $this->encryption == 'ssl' ? 'ldaps://' . $this->hostname : $this->hostname;
    $resource = ldap_connect($url, $this->port);
    if ($resource !== FALSE) {
      $bind = ldap_bind($resource, $binddn, $bindpw);
      if ($bind !== FALSE) {
        ldap_unbind($resource);
        return TRUE;
      }
    }
    return FALSE;
  }

}
