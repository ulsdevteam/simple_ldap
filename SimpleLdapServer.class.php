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
  protected $host;
  protected $port;
  protected $starttls = FALSE;

  // Require LDAPv3.
  protected $version = 3;

  // LDAP directory parameters.
  protected $binddn;
  protected $bindpw;
  protected $pagesize = FALSE;

  // LDAP resource link.
  protected $resource = FALSE;
  protected $bound = FALSE;

  // Special LDAP entries.
  protected $rootdse;
  protected $schema;

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
   * Constructor.
   *
   * This constructor builds the object by pulling the configuration parameters
   * from the Drupal variable system.
   */
  public function __construct() {
    $this->host = variable_get('simple_ldap_host');
    $this->port = variable_get('simple_ldap_port', 389);
    $this->starttls = variable_get('simple_ldap_starttls', FALSE);
    $this->binddn = variable_get('simple_ldap_binddn');
    $this->bindpw = variable_get('simple_ldap_bindpw');

    // Only set the pagesize if paged queries are supported.
    if (function_exists('ldap_control_paged_result_response') &&
        function_exists('ldap_control_paged_result')) {
      $this->pagesize = variable_get('simple_ldap_pagesize');
    }

    $this->bind();
  }

  /**
   * Destructor.
   */
  public function __destruct() {
    $this->unbind();
  }

  /**
   * Magic __get() function.
   */
  public function __get($name) {
    switch ($name) {
      case 'rootdse':
        // Load the rootDSE.
        $this->rootdse();
        break;

      case 'schema':
      case 'subschema':
        // Load the schema.
        $this->schema();
        return $this->schema;
        break;

      case 'error':
        return ldap_errno($this->resource);
        break;

      // Handle PHP ldap options.
      case 'LDAP_OPT_DEREF':
      case 'LDAP_OPT_SIZELIMIT':
      case 'LDAP_OPT_TIMELIMIT':
      case 'LDAP_OPT_NETWORK_TIMEOUT':
      case 'LDAP_OPT_PROTOCOL_VERSION':
      case 'LDAP_OPT_ERROR_NUMBER':
      case 'LDAP_OPT_REFERRALS':
      case 'LDAP_OPT_RESTART':
      case 'LDAP_OPT_HOST_NAME':
      case 'LDAP_OPT_ERROR_STRING':
      case 'LDAP_OPT_MATCHED_DN':
      case 'LDAP_OPT_SERVER_CONTROLS':
      case 'LDAP_OPT_CLIENT_CONTROLS':
        $this->connect();
        $result = @ldap_get_option($this->resource, constant($name), $value);
        if ($result !== FALSE) {
          return $value;
        }
        return FALSE;
        break;
    }

    return $this->$name;
  }

  /**
   * Magic __set() function, handles changing server settings.
   */
  public function __set($name, $value) {
    switch ($name) {
      case 'host':
      case 'port':
      case 'starttls':
        $this->disconnect();
      case 'binddn':
      case 'bindpw':
        $this->unbind();
      case 'pagesize':
        $this->$name = $value;
        break;

      // Handle PHP LDAP options.
      case 'LDAP_OPT_DEREF':
      case 'LDAP_OPT_SIZELIMIT':
      case 'LDAP_OPT_TIMELIMIT':
      case 'LDAP_OPT_NETWORK_TIMEOUT':
      case 'LDAP_OPT_ERROR_NUMBER':
      case 'LDAP_OPT_REFERRALS':
      case 'LDAP_OPT_RESTART':
      case 'LDAP_OPT_HOST_NAME':
      case 'LDAP_OPT_ERROR_STRING':
      case 'LDAP_OPT_MATCHED_DN':
      case 'LDAP_OPT_SERVER_CONTROLS':
      case 'LDAP_OPT_CLIENT_CONTROLS':
        $this->connect();
        @ldap_get_option($this->resource, constant($name), $old_value);
        $result = @ldap_set_option($this->resource, constant($name), $value);
        if ($result && $old_value != $value) {
          $this->unbind();
        }
        break;

      // LDAPv3 is required, do not allow it to be changed.
      case 'LDAP_OPT_PROTOCOL_VERSION':
        return FALSE;
        break;

      default:
    }
  }

  /**
   * Connect and bind to the LDAP server.
   *
   * @param mixed $binddn
   *   Use the given DN while binding. This sets the object's binddn to this
   *   value, and rebinds if already bound. The default is FALSE because NULL is
   *   a valid binddn for an anonymous bind.
   * @param mixed $bindpw
   *   Use the given password while binding. This sets the object's bindpw to
   *   this value, and rebinds if already bound. The default is FALSE because
   *   NULL is a valid binddn for an anonymous bind.
   *
   * @return boolean
   *   TRUE on success, FALSE on failure.
   */
  public function bind($binddn = FALSE, $bindpw = FALSE) {
    // Connect first.
    if ($this->connect() === FALSE) {
      return FALSE;
    }

    // Reset bind DN if provided.
    if ($binddn && $binddn != $this->binddn) {
      $this->binddn = $binddn;
      $this->bound = FALSE;
    }

    // Reset bind PW if provided.
    if ($bindpw && $bindpw != $this->bindpw) {
      $this->bindpw = $bindpw;
      $this->bound = FALSE;
    }

    if (!$this->bound) {
      // Start TLS if enabled.
      if ($this->starttls) {
        $tls = @ldap_start_tls($this->resource);
        if ($tls === FALSE) {
          return FALSE;
        }
      }

      // Bind to the LDAP server.
      $this->bound = @ldap_bind($this->resource, $this->binddn, $this->bindpw);

      // If paged queries are enabled, verify whether the server supports them.
      if ($this->bound && $this->pagesize) {
        // Load the rootDSE.
        $this->rootdse();

        // Look for the paged query OID supported control.
        if (!in_array('1.2.840.113556.1.4.319', $this->rootdse['supportedcontrol'])) {
          $this->pagesize = FALSE;
        }
      }

    }

    return $this->bound;
  }

  /**
   * Unbind from the LDAP server.
   *
   * @return boolean
   *   TRUE on success, FALSE on failure.
   */
  public function unbind() {
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

    // Use a post-test loop (do/while) because this will always be done once. It
    // will only loop if paged queries are supported/enabled, and more than one
    // page is available.
    $entries = array('count' => 0);
    $cookie = '';
    do {

      if ($this->pagesize) {
        // Set the paged query cookie.
        ldap_control_paged_result($this->resource, $this->pagesize, TRUE, $cookie);
      }

      // Perform the search based on the scope provided.
      switch ($scope) {
        case 'base':
          $result = @ldap_read($this->resource, $base_dn, $filter, $attributes, $attrsonly, $sizelimit, $timelimit, $deref);
          break;

        case 'one':
          $result = @ldap_list($this->resource, $base_dn, $filter, $attributes, $attrsonly, $sizelimit, $timelimit, $deref);
          break;

        case 'sub':
        default:
          $result = @ldap_search($this->resource, $base_dn, $filter, $attributes, $attrsonly, $sizelimit, $timelimit, $deref);
          break;
      }

      if ($this->pagesize) {
        // Merge page into $entries.
        $e = @ldap_get_entries($this->resource, $result);
        $entries['count'] += $e['count'];
        for ($i = 0; $i < $e['count']; $i++) {
          $entries[] = $e[$i]; 
        }

        // Get the paged query response cookie.
        @ldap_control_paged_result_response($this->resource, $result, $cookie);
      }
      else {
        $entries = @ldap_get_entries($this->resource, $result);
      }

    } while ($cookie !== NULL && $cookie != '');

    return $this->clean($entries);
  }

  /**
   * Check whether the provided DN exists.
   */
  public function exists($dn) {
    $entry = $this->search($dn, '(objectclass=*)', 'base', array('dn'));
    if ($entry === FALSE || count($entry) == 0) {
      return FALSE;
    }
    return TRUE;
  }

  /**
   * Add an entry to the LDAP directory.
   */
  public function add($dn, $attributes) {
    // Make sure there is a valid binding.
    if (!$this->bind()) {
      return FALSE;
    }

    // Add the entry.
    return @ldap_add($this->resource, $dn, $attributes);
  }

  /**
   * Delete an entry from the directory.
   */
  public function delete($dn, $recursive = FALSE) {
    // Make sure there is a valid binding.
    if (!$this->bind()) {
      return FALSE;
    }

    if ($recursive) {
      $subentries = $this->search($dn, '(objectclass=*)', 'one', array('dn'));
      foreach ($subentries as $subdn => $entry) {
        if (!$this->delete($subdn, TRUE)) {
          return FALSE;
        }
      }
    }

    return @ldap_delete($this->resource, $dn);
  }

  /**
   * Modify an LDAP entry.
   */
  public function modify($dn, $attributes) {
    // Make sure there is a valid binding.
    if (!$this->bind()) {
      return FALSE;
    }

    // Add the entry.
    return @ldap_modify($this->resource, $dn, $attributes);
  }

  /**
   * Connect to the LDAP server.
   *
   * @return boolean
   *   TRUE on success, FALSE on failure.
   */
  protected function connect() {
    if ($this->resource === FALSE) {
      $this->resource = @ldap_connect($this->host, $this->port);
      if ($this->resource === FALSE) {
        return FALSE;
      }
    }

    // Set the LDAP version
    @ldap_set_option($this->resource, LDAP_OPT_PROTOCOL_VERSION, $this->version);

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
   * Loads the server's rootDSE.
   */
  protected function rootdse() {
    if (!is_array($this->rootdse)) {
      $attributes = array(
        'vendorName',
        'vendorVersion',
        'namingContexts',
        'altServer',
        'supportedExtension',
        'supportedControl',
        'supportedSASLMechanisms',
        'supportedLDAPVersion',
        'subschemaSubentry',
      );

      $result = $this->search('', 'objectclass=*', 'base', $attributes);
      $this->rootdse = $result[''];
    }

  }

  /**
   * Loads the server's schema.
   */
  protected function schema() {
    if (!isset($this->schema)) {
      $this->schema = new SimpleLdapSchema($this);
    }
  }

  /**
   * Cleans up an array returned by the ldap_* functions.
   */
  protected function clean($entry) {
    if (is_array($entry)) {
      $clean = array();
      for ($i = 0; $i < $entry['count']; $i++) {
        $clean[$entry[$i]['dn']] = array();
        for ($j = 0; $j < $entry[$i]['count']; $j++) {
          $clean[$entry[$i]['dn']][$entry[$i][$j]] = array();
          for ($k = 0; $k < $entry[$i][$entry[$i][$j]]['count']; $k++) {
            $clean[$entry[$i]['dn']][$entry[$i][$j]][] = $entry[$i][$entry[$i][$j]][$k];
          }
        }
      }
      return $clean;
    }

    return FALSE;
  }

}
