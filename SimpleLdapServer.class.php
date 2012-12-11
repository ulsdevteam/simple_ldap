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
  protected static $instance;

  // LDAP connection parameters.
  protected $host;
  protected $port;
  protected $starttls = FALSE;

  // Require LDAPv3.
  protected $version = 3;

  // LDAP directory parameters.
  protected $binddn;
  protected $bindpw;
  protected $basedn;

  // LDAP server type (OpenLDAP, Active Directory, etc.).
  protected $type;

  // LDAP resource link.
  protected $resource = FALSE;
  protected $bound = FALSE;

  // Special LDAP entries.
  protected $rootdse;
  protected $schema;

  // Options.
  protected $pagesize = FALSE;
  protected $readonly;

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
    $this->readonly = variable_get('simple_ldap_readonly', FALSE);

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

      case 'basedn':
        // Load the baseDN.
        $this->basedn();
        break;

      case 'type':
        // Determine the directory type.
        $this->type();
        break;

      case 'schema':
      case 'subschema':
        // Load the schema.
        $this->schema();
        return $this->schema;

      case 'error':
        return ldap_errno($this->resource);

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
        $result = self::ldap_get_option($this->resource, constant($name), $value);
        if ($result !== FALSE) {
          return $value;
        }
        return FALSE;
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
        self::ldap_get_option($this->resource, constant($name), $old_value);
        $result = self::ldap_set_option($this->resource, constant($name), $value);
        if ($result && $old_value != $value) {
          $this->unbind();
        }
        break;

      // LDAPv3 is required, do not allow it to be changed.
      case 'LDAP_OPT_PROTOCOL_VERSION':
        return FALSE;

      default:
    }
  }

  /**
   * Connect and bind to the LDAP server.
   *
   * @param mixed $binddn
   *   Use the given DN while binding. Use NULL for an anonymous bind.
   * @param mixed $bindpw
   *   Use the given password while binding. Use NULL for an anonymous bind.
   * @param boolean $rebind
   *   Reset the object's bind credentials to those provided. Otherwise, just
   *   bind to verify that the credentials are valid.
   *
   * @return boolean
   *   TRUE on success, FALSE on failure.
   */
  public function bind($binddn = FALSE, $bindpw = FALSE, $rebind = FALSE) {
    // Connect first.
    if ($this->connect() === FALSE) {
      return FALSE;
    }

    // Reset bind DN if provided, and reset is specified.
    if ($rebind && $binddn !== FALSE && $binddn != $this->binddn) {
      $this->binddn = $binddn;
      $this->bound = FALSE;
    }

    // Reset bind PW if provided, and reset is specified.
    if ($rebind && $bindpw !== FALSE && $bindpw != $this->bindpw) {
      $this->bindpw = $bindpw;
      $this->bound = FALSE;
    }

    // Attempt to bind if not already bound, or rebind is specified, or
    // credentials are given.
    if (!$this->bound || $rebind || $binddn !== FALSE && $bindpw !== FALSE) {

      // Bind to the LDAP server.
      if ($rebind || $binddn === FALSE || $bindpw === FALSE) {
        $this->bound = self::ldap_bind($this->resource, $this->binddn, $this->bindpw);
      }
      else {
        // Bind with the given credentials. This is a temporary bind to verify
        // the password, so $this->bound is reset to FALSE.
        $result = self::ldap_bind($this->resource, $binddn, $bindpw);
        $this->bound = FALSE;
        return $result;
      }

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
  public function search($base_dn, $filter = 'objectclass=*', $scope = 'sub', $attributes = array(), $attrsonly = 0, $sizelimit = 0, $timelimit = 0, $deref = LDAP_DEREF_NEVER) {
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
        self::ldap_control_paged_result($this->resource, $this->pagesize, FALSE, $cookie);
      }

      // Perform the search based on the scope provided.
      switch ($scope) {
        case 'base':
          $result = self::ldap_read($this->resource, $base_dn, $filter, $attributes, $attrsonly, $sizelimit, $timelimit, $deref);
          break;

        case 'one':
          $result = self::ldap_list($this->resource, $base_dn, $filter, $attributes, $attrsonly, $sizelimit, $timelimit, $deref);
          break;

        case 'sub':
        default:
          $result = self::ldap_search($this->resource, $base_dn, $filter, $attributes, $attrsonly, $sizelimit, $timelimit, $deref);
          break;
      }

      if ($this->pagesize) {
        // Merge page into $entries.
        $e = self::ldap_get_entries($this->resource, $result);
        $entries['count'] += $e['count'];
        for ($i = 0; $i < $e['count']; $i++) {
          $entries[] = $e[$i];
        }

        // Get the paged query response cookie.
        self::ldap_control_paged_result_response($this->resource, $result, $cookie);
      }
      else {
        $entries = self::ldap_get_entries($this->resource, $result);
      }

      // Free the query result memory.
      self::ldap_free_result($result);

    } while ($cookie !== NULL && $cookie != '');

    // ldap_get_entries returns NULL if ldap_read does not find anything.
    // Reformat the result into something consistent with the other search
    // types.
    if ($entries === NULL) {
      $entries = array('count' => 0);
    }

    return $entries;
  }

  /**
   * Check whether the provided DN exists.
   */
  public function exists($dn) {
    $entry = $this->search($dn, '(objectclass=*)', 'base', array('dn'));
    if ($entry === FALSE || $entry['count'] == 0) {
      return FALSE;
    }
    return TRUE;
  }

  /**
   * Gets a single entry from the LDAP server.
   */
  public function entry($dn) {
    $entry = $this->search($dn, '(objectclass=*)', 'base');
    return $this->clean($entry);
  }

  /**
   * Compare the given attribute value with what is in the LDAP server.
   */
  public function compare($dn, $attribute, $value) {
    // Make sure there is a valid binding.
    if (!$this->bind()) {
      return FALSE;
    }

    return self::ldap_compare($this->resource, $dn, $attribute, $value);
  }

  /**
   * Add an entry to the LDAP directory.
   */
  public function add($dn, $attributes) {
    // Make sure there is a valid binding and that changes are allowed.
    if ($this->readonly || !$this->bind()) {
      return FALSE;
    }

    // Verify that there are no empty attributes.
    foreach ($attributes as $key => $value) {
      if (is_array($value)) {
        foreach ($value as $k => $v) {
          if (empty($v)) {
            unset($value[$k]);
          }
        }

        if (isset($value['count'])) {
          unset($attributes[$key]['count']);
        }

        if (count($value) == 0) {
          unset($attributes[$key]);
        }

      }
    }

    // Add the entry.
    return self::ldap_add($this->resource, $dn, $attributes);
  }

  /**
   * Delete an entry from the directory.
   */
  public function delete($dn, $recursive = FALSE) {
    // Make sure there is a valid binding and that changes are allowed.
    if ($this->readonly || !$this->bind()) {
      return FALSE;
    }

    if ($recursive) {
      $subentries = $this->clean($this->search($dn, '(objectclass=*)', 'one', array('dn')));
      foreach ($subentries as $subdn => $entry) {
        if (!$this->delete($subdn, TRUE)) {
          return FALSE;
        }
      }
    }

    return self::ldap_delete($this->resource, $dn);
  }

  /**
   * Modify an LDAP entry.
   */
  public function modify($dn, $attributes, $type = NULL) {
    // Make sure there is a valid binding and that changes are allowed.
    if ($this->readonly || !$this->bind()) {
      return FALSE;
    }

    switch ($type) {
      case 'add':
        $result = self::ldap_mod_add($this->resource, $dn, $attributes);
        break;

      case 'del':
      case 'delete':
        $result = self::ldap_mod_del($this->resource, $dn, $attributes);
        break;

      case 'replace':
        $result = self::ldap_mod_replace($this->resource, $dn, $attributes);
        break;

      default:
        $result = self::ldap_modify($this->resource, $dn, $attributes);
    }

    return $result;
  }

  /**
   * Move an entry to a new DN.
   *
   * @return boolean
   *   TRUE on success, FALSE on failure.
   */
  public function move($dn, $newdn, $deleteoldrdn = TRUE) {
    // Make sure there is a valid binding and that changes are allowed.
    if ($this->readonly || !$this->bind()) {
      return FALSE;
    }

    // Parse $newdn into a format that ldap_rename() can use.
    $parts = ldap_explode_dn($newdn, 0);
    $rdn = $parts[0];
    $parent = '';
    for ($i = 1; $i < $parts['count']; $i++) {
      $parent .= $parts[$i];
      if ($i < $parts['count'] - 1) {
        $parent .= ',';
      }
    }

    // Move the entry.
    $result = ldap_rename($this->resource, $dn, $rdn, $parent, $deleteoldrdn);

    // Return the result.
    return $result;
  }

  /**
   * Copy an entry to a new DN.
   *
   * @return boolean
   *   TRUE on success, FALSE on failure.
   */
  public function copy($dn, $newdn) {
    // Make sure there is a valid binding and that changes are allowed.
    if ($this->readonly || !$this->bind()) {
      return FALSE;
    }

    self::ldap_get_option($this->resource, LDAP_OPT_CLIENT_CONTROLS, $controls);

    $entry = $this->entry($dn);
    if ($entry !== FALSE) {
      $result = $this->add($newdn, $entry[$dn]);
    }

    return FALSE;
  }

  /**
   * Connect to the LDAP server.
   *
   * @return boolean
   *   TRUE on success, FALSE on failure.
   */
  protected function connect() {
    if ($this->resource === FALSE) {

      // Set up the connection.
      $this->resource = self::ldap_connect($this->host, $this->port);
      if ($this->resource === FALSE) {
        return FALSE;
      }

      // Set the LDAP version.
      if (!self::ldap_set_option($this->resource, LDAP_OPT_PROTOCOL_VERSION, $this->version)) {
        return FALSE;
      }

      // StartTLS.
      if ($this->starttls) {
        if (!self::ldap_start_tls($this->resource)) {
          return FALSE;
        }
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
        'objectClass',
        'rootDomainNamingContext',
      );

      $result = $this->clean($this->search('', 'objectclass=*', 'base', $attributes));
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
   * Attempts to determine the server's baseDN.
   */
  protected function basedn() {
    // If the baseDN has already been checked, just return it.
    if (isset($this->basedn)) {
      return $this->basedn;
    }

    // Check if the basedn is specified in the module configuration.
    $basedn = variable_get('simple_ldap_basedn');
    if (!empty($basedn)) {
      $this->basedn = $basedn;
      return $this->basedn;
    }

    // The basedn is not specified, so attempt to detect it from the rootDSE.
    $this->rootdse();
    if (isset($this->rootdse['namingcontexts'])) {
      $this->basedn = $this->rootdse['namingcontexts'][0];
      return $this->basedn;
    }

    // Unable to determine the baseDN.
    return FALSE;
  }

  /**
   * Cleans up an array returned by the ldap_* functions.
   */
  public function clean($entry) {
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

  /**
   * Attempts to detect the directory type using the rootDSE.
   */
  protected function type() {
    // If the type has already been determined, return it.
    if (isset($this->type)) {
      return $this->type;
    }

    // Load the rootDSE.
    $this->rootdse();

    // Check for OpenLDAP.
    if (isset($this->rootdse['objectclass']) && is_array($this->rootdse['objectclass'])) {
      if (in_array('OpenLDAProotDSE', $this->rootdse['objectclass'])) {
        $this->type = 'OpenLDAP';
        return $this->type;
      }
    }

    // Check for Active Directory.
    if (isset($this->rootdse['rootdomainnamingcontext'])) {
      $this->type = 'Active Directory';
      return $this->type;
    }

    // Default to generic LDAPv3.
    $this->type = 'LDAP';
    return $this->type;
  }

  /**
   * Wrapper function for ldap_add().
   *
   * @param resource $link_identifier
   *   An LDAP link identifier.
   * @param string $dn
   *   The distinguished name of an LDAP entity.
   * @param array $entry
   *   An array that specifies the information about the entry. The values in
   *   the entries are indexed by individual attributes. In case of multiple
   *   values for an attribute, they are indexed using integers starting with 0.
   *
   * @return boolean
   *   TRUE on success.
   *
   * @throw SimpleLdapException
   */
  protected static function ldap_add($link_identifier, $dn, $entry) {
    // Wrapped function call.
    $return = @ldap_add($link_identifier, $dn, $entry);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link_identifier = @link_identifier, $dn = @dn, $entry = @entry) returns @return';
      $variables = array(
        '@link_identifier' => print_r($link_identifier, TRUE),
        '@dn' => print_r($dn, TRUE),
        '@entry' => print_r($entry, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return === FALSE) {
      throw new SimpleLdapException($link_identifier);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_bind().
   *
   * @param resource $link_identifier
   *   An LDAP link identifier.
   * @param string $bind_rdn
   *   The RDN to bind with. If not specified, and anonymous bind is attempted.
   * @param string $bind_password
   *   The password to use during the bind.
   *
   * @return boolean
   *   Returns TRUE on success or FALSE on failure.
   */
  protected static function ldap_bind($link_identifier, $bind_rdn = NULL, $bind_password = NULL) {
    // Wrapped function call.
    $return = @ldap_bind($link_identifier, $bind_rdn, $bind_password);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link_identifier = @link_identifier, $bind_rdn = @bind_rdn, $bind_password = @bind_password) returns @return';
      $variables = array(
        '@link_identifier' => print_r($link_identifier, TRUE),
        '@bind_rdn' => print_r($bind_rdn, TRUE),
        '@bind_password' => print_r($bind_password, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_compare().
   *
   * @param resource $link_identifier
   *   An LDAP link identifier.
   * @param string $dn
   *   The distinguished name of an LDAP entity.
   * @param string $attribute
   *   The attribute name.
   * @param string $value
   *   The compared value.
   *
   * @return boolean
   *   Returns TRUE if value matches otherwise returns FALSE.
   *
   * @throw SimpleLdapException
   */
  protected static function ldap_compare($link_identifier, $dn, $attribute, $value) {
    // Wrapped function call.
    $return = @ldap_compare($link_identifier, $dn, $attribute, $value);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link_identifier = @link_identifier, $dn = @dn, $attribute = @attribute, $value = @value) returns @return';
      $variables = array(
        '@link_identifier' => print_r($link_identifier, TRUE),
        '@dn' => print_r($dn, TRUE),
        '@attribute' => print_r($attribute, TRUE),
        '@value' => print_r($value, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return == -1) {
      throw new SimpleLdapException($link_identifier);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_connect().
   *
   * @param string $hostname
   *   If you are using OpenLDAP 2.x.x you can specify a URL instead of the
   *   hostname. To use LDAP with SSL, compile OpenLDAP 2.x.x with SSL support,
   *   configure PHP with SSL, and set this parameter as ldaps://hostname/
   * @param int $port
   *   The port to connect to. Not used when using URLs.
   *
   * @return resource
   *   LDAP link identifier
   *
   * @throw SimpleLdapException
   */
  protected static function ldap_connect($hostname = NULL, $port = 389) {
    // Wrapped function call.
    $return = @ldap_connect($hostname, $port);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($hostname = @hostname, $port = @port) returns @return';
      $variables = array(
        '@hostname' => print_r($hostname, TRUE),
        '@port' => print_r($port, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return == FALSE) {
      throw new SimpleLdapException($link_identifier);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_control_paged_result().
   *
   * @param resource $link_identifier
   *   An LDAP link identifier.
   * @param int $pagesize
   *   The number of entries by page.
   * @param boolean $iscritical
   *   Indicates whether the pagination is critical of not. If true and if the
   *   server doesn't support pagination, the search will return no result.
   * @param string $cookie
   *   An opaque structure sent by the server.
   *
   * @return boolean
   *   TRUE on success.
   *
   * @throw SimpleLdapException
   *
   * @todo Default values for $pagesize, $iscritical, $cookie.
   */
  protected static function ldap_control_paged_result($link, $pagesize, $iscritical, $cookie) {
    // Wrapped function call.
    $return = @ldap_control_paged_result($link, $pagesize, $iscritical, $cookie);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link = @link, $pagesize = @pagesize, $iscritical = @iscritical, $cookie = @cookie) returns @return';
      $variables = array(
        '@link' => print_r($link, TRUE),
        '@pagesize' => print_r($pagesize, TRUE),
        '@iscritical' => print_r($iscritical, TRUE),
        '@cookie' => print_r($cookie, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return === FALSE) {
      throw new SimpleLdapException($link);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_control_paged_result_response().
   *
   * @param resource $link
   *   An LDAP link identifier.
   * @param resouce $result
   *   An LDAP search result identifier.
   * @param string $cookie
   *   An opaque structure sent by the server.
   * @param int $estimated
   *   The estimated number of entries to retrieve.
   *
   * @return boolean
   *   TRUE on success.
   *
   * @throw SimpleLdapException
   */
  protected static function ldap_control_paged_result_response($link, $result, &$cookie, &$estimated) {
    // Wrapped function call.
    $return = @ldap_control_paged_result_response($link, $result, $cookie, $estimated);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link = @link, $result = @result, $cookie = @cookie, $estimated = @estimated) returns @return';
      $variables = array(
        '@link' => print_r($link, TRUE),
        '@result' => print_r($result, TRUE),
        '@cookie' => print_r($cookie, TRUE),
        '@estimated' => print_r($estimated, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return === FALSE) {
      throw new SimpleLdapException($link);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_delete().
   *
   * @param resource $link_identifier
   *   An LDAP link identifier.
   * @param string $dn
   *   The distinguished name of an LDAP entity.
   *
   * @return boolean
   *   TRUE on success.
   *
   * @throw SimpleLdapException
   */
  protected static function ldap_delete($link_identifier, $dn) {
    // Wrapped function call.
    $return = @ldap_delete($link_identifier, $dn);

    // Debugging.
    if (variable_get('simple_ldap_debug', ERROR)) {
      $message = __FUNCTION__ . '($link_identifier = @link_identifier, $dn = @dn) returns @return';
      $variables = array(
        '@link_identifier' => print_r($link_identifier, TRUE),
        '@dn' => print_r($dn, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return === FALSE) {
      throw new SimpleLdapException($link_identifier);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_free_result().
   *
   * @param resource $result_identifier
   *   LDAP search result identifier.
   *
   * @return boolean
   *   TRUE on success.
   *
   * @throw SimpleLdapException
   */
  protected static function ldap_free_result($result_identifier) {
    // Wrapped function call.
    $return = @ldap_free_result($result_identifier);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($result_identifier = @result_identifier) returns @return';
      $variables = array(
        '@result_identifier' => print_r($result_identifier, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return === FALSE) {
      throw new SimpleLdapException($result_identifier);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_get_entries().
   *
   * @param resource $link_identifier
   *   An LDAP link identifier.
   * @param resource $result_identifier
   *   An LDAP search result identifier.
   *
   * @return array
   *
   * @throw SimpleLdapException
   */
  protected static function ldap_get_entries($link_identifier, $result_identifier) {
    // Wrapped function call.
    $return = @ldap_get_entries($link_identifier, $result_identifier);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link_identifier = @link_identifier, $result_identifier = @result_identifier) returns @return';
      $variables = array(
        '@link_identifier' => print_r($link_identifier, TRUE),
        '@result_identifier' => print_r($result_identifier, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return === FALSE) {
      throw new SimpleLdapException($link_identifier);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_get_option().
   *
   * @param resource $link_identifier
   *   An LDAP link identifier.
   * @param int $option
   *   The parameter option.
   *   @see http://us2.php.net/manual/en/function.ldap-get-option.php
   * @param mixed $retval
   *   This will be set to the option value.
   *
   * @return boolean
   *   TRUE on success.
   *
   * @throw SimpleLdapException
   */
  protected static function ldap_get_option($link_identifier, $option, &$retval) {
    // Wrapped function call.
    $return = @ldap_get_option($link_identifier, $option, $retval);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link_identifier = @link_identifier, $option = @option, $retval = @retval) returns @return';
      $variables = array(
        '@link_identifier' => print_r($link_identifier, TRUE),
        '@option' => print_r($option, TRUE),
        '@retval' => print_r($retval, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return === FALSE) {
      throw new SimpleLdapException($link_identifier);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_list().
   *
   * @param resource $link_identifier
   *   An LDAP link identifier.
   * @param string $basedn
   *   The base DN for the directory.
   * @param string $filter
   *   The LDAP filter to apply.
   * @param array $attributes
   *   An array of the required attributes.
   * @param int $attrsonly
   *   Should be set to 1 if only attribute types are wanted. If set to 0 both
   *   attributes types and attribute values are fetched which is the default
   *   behaviour.
   * @param int $sizelimit
   *   Enables you to limit the count of entries fetched. Setting this to 0
   *   means no limit.
   * @param int $timelimit
   *   Sets the number of seconds how long is spend on the search. Setting this
   *   to 0 means no limit.
   * @param int $deref
   *   Specifies how aliases should be handled during the search.
   *
   * @return resource
   *   LDAP search result identifier.
   *
   * @throw SimpleLdapException
   *
   * @todo debug $result
   */
  protected static function ldap_list($link_identifier, $base_dn, $filter, $attributes = array(), $attrsonly = 0, $sizelimit = 0, $timelimit = 0, $deref) {
    // Wrapped function call.
    $return = @ldap_list($link_identifier, $base_dn, $filter, $attributes, $attrsonly, $sizelimit, $timelimit, $deref);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link_identifier = @link_identifier, $base_dn = @base_dn, $filter = @filter, $attributes = @attributes, $attrsonly = @attrsonly, $sizelimit = @sizelimit, $timelimit = @timelimit, $deref = @deref) returns @return';
      $variables = array(
        '@link_identifier' => print_r($link_identifier, TRUE),
        '@base_dn' => print_r($base_dn, TRUE),
        '@filter' => print_r($filter, TRUE),
        '@attributes' => print_r($attributes, TRUE),
        '@attrsonly' => print_r($attrsonly, TRUE),
        '@sizelimit' => print_r($sizelimit, TRUE),
        '@timelimit' => print_r($timelimit, TRUE),
        '@deref' => print_r($deref, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return === FALSE) {
      throw new SimpleLdapException($link_identifier);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_mod_add().
   *
   * @param resource $link_identifier
   *   An LDAP link identifier.
   * @param string $dn
   *   The distinguished name of an LDAP entity.
   * @param array $entry
   *   An array that specifies the information about the entry. The values in
   *   the entries are indexed by individual attributes. In case of multiple
   *   values for an attribute, they are indexed using integers starting with 0.
   *
   * @return boolean
   *   TRUE on success.
   *
   * @throw SimpleLdapException
   */
  protected static function ldap_mod_add($link_identifier, $dn, $entry) {
    // Wrapped function call.
    $return = @ldap_mod_add($link_identifier, $dn, $entry);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link_identifier = @link_identifier, $dn = @dn, $entry = @entry) returns @return';
      $variables = array(
        '@link_identifier' => print_r($link_identifier, TRUE),
        '@dn' => print_r($dn, TRUE),
        '@entry' => print_r($entry, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return === FALSE) {
      throw new SimpleLdapException($link_identifier);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_mod_del().
   *
   * @param resource $link_identifier
   *   An LDAP link identifier.
   * @param string $dn
   *   The distinguished name of an LDAP entity.
   * @param array $entry
   *   An array that specifies the information about the entry. The values in
   *   the entries are indexed by individual attributes. In case of multiple
   *   values for an attribute, they are indexed using integers starting with 0.
   *
   * @return boolean
   *   TRUE on success.
   *
   * @throw SimpleLdapException
   */
  protected static function ldap_mod_del($link_identifier, $dn, $entry) {
    // Wrapped function call.
    $return = @ldap_mod_del($link_identifier, $dn, $entry);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link_identifier = @link_identifier, $dn = @dn, $entry = @entry) returns @return';
      $variables = array(
        '@link_identifier' => print_r($link_identifier, TRUE),
        '@dn' => print_r($dn, TRUE),
        '@entry' => print_r($entry, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return === FALSE) {
      throw new SimpleLdapException($link_identifier);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_mod_replace().
   *
   * @param resource $link_identifier
   *   An LDAP link identifier.
   * @param string $dn
   *   The distinguished name of an LDAP entity.
   * @param array $entry
   *   An array that specifies the information about the entry. The values in
   *   the entries are indexed by individual attributes. In case of multiple
   *   values for an attribute, they are indexed using integers starting with 0.
   *
   * @return boolean
   *   TRUE on success.
   *
   * @throw SimpleLdapException
   */
  protected static function ldap_mod_replace($link_identifier, $dn, $entry) {
    // Wrapped function call.
    $return = @ldap_mod_replace($link_identifier, $dn, $entry);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link_identifier = @link_identifier, $dn = @dn, $entry = @entry) returns @return';
      $variables = array(
        '@link_identifier' => print_r($link_identifier, TRUE),
        '@dn' => print_r($dn, TRUE),
        '@entry' => print_r($entry, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return === FALSE) {
      throw new SimpleLdapException($link_identifier);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_modify().
   *
   * @param resource $link_identifier
   *   An LDAP link identifier.
   * @param string $dn
   *   The distinguished name of an LDAP entity.
   * @param array $entry
   *   An array that specifies the information about the entry. The values in
   *   the entries are indexed by individual attributes. In case of multiple
   *   values for an attribute, they are indexed using integers starting with 0.
   *
   * @return boolean
   *   TRUE on success.
   *
   * @throw SimpleLdapException
   */
  protected static function ldap_modify($link_identifier, $dn, $entry) {
    // Wrapped function call.
    $return = @ldap_modify($link_identifier, $dn, $entry);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link_identifier = @link_identifier, $dn = @dn, $entry = @entry) returns @return';
      $variables = array(
        '@link_identifier' => print_r($link_identifier, TRUE),
        '@dn' => print_r($dn, TRUE),
        '@entry' => print_r($entry, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return === FALSE) {
      throw new SimpleLdapException($link_identifier);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_read().
   *
   * @param resource $link_identifier
   *   An LDAP link identifier.
   * @param string $basedn
   *   The base DN for the directory.
   * @param string $filter
   *   The LDAP filter to apply.
   * @param array $attributes
   *   An array of the required attributes.
   * @param int $attrsonly
   *   Should be set to 1 if only attribute types are wanted. If set to 0 both
   *   attributes types and attribute values are fetched which is the default
   *   behaviour.
   * @param int $sizelimit
   *   Enables you to limit the count of entries fetched. Setting this to 0
   *   means no limit.
   * @param int $timelimit
   *   Sets the number of seconds how long is spend on the search. Setting this
   *   to 0 means no limit.
   * @param int $deref
   *   Specifies how aliases should be handled during the search.
   *
   * @return resource
   *   LDAP search result identifier.
   *
   * @throw SimpleLdapException
   *
   * @todo debug $result
   */
  protected static function ldap_read($link_identifier, $base_dn, $filter, $attributes = array(), $attrsonly = 0, $sizelimit = 0, $timelimit = 0, $deref = LDAP_DEREF_NEVER) {
    // Wrapped function call.
    $return = @ldap_read($link_identifier, $base_dn, $filter, $attributes, $attrsonly, $sizelimit, $timelimit, $deref);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link_identifier = @link_identifier, $base_dn = @base_dn, $filter = @filter, $attributes = @attributes, $attrsonly = @attrsonly, $sizelimit = @sizelimit, $timelimit = @timelimit, $deref = @deref) returns @return';
      $variables = array(
        '@link_identifier' => print_r($link_identifier, TRUE),
        '@base_dn' => print_r($base_dn, TRUE),
        '@filter' => print_r($filter, TRUE),
        '@attributes' => print_r($attributes, TRUE),
        '@attrsonly' => print_r($attrsonly, TRUE),
        '@sizelimit' => print_r($sizelimit, TRUE),
        '@timelimit' => print_r($timelimit, TRUE),
        '@deref' => print_r($deref, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return === FALSE) {
      throw new SimpleLdapException($link_identifier);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_search().
   *
   * @param resource $link_identifier
   *   An LDAP link identifier.
   * @param string $basedn
   *   The base DN for the directory.
   * @param string $filter
   *   The LDAP filter to apply.
   * @param array $attributes
   *   An array of the required attributes.
   * @param int $attrsonly
   *   Should be set to 1 if only attribute types are wanted. If set to 0 both
   *   attributes types and attribute values are fetched which is the default
   *   behaviour.
   * @param int $sizelimit
   *   Enables you to limit the count of entries fetched. Setting this to 0
   *   means no limit.
   * @param int $timelimit
   *   Sets the number of seconds how long is spend on the search. Setting this
   *   to 0 means no limit.
   * @param int $deref
   *   Specifies how aliases should be handled during the search.
   *
   * @return resource
   *   LDAP search result identifier.
   *
   * @throw SimpleLdapException
   *
   * @todo debug $result
   */
  protected static function ldap_search($link_identifier, $base_dn, $filter, $attributes = array(), $attrsonly = 0, $sizelimit = 0, $timelimit = 0, $deref = LDAP_DEREF_NEVER) {
    // Wrapped function call.
    $return = @ldap_search($link_identifier, $base_dn, $filter, $attributes, $attrsonly, $sizelimit, $timelimit, $deref);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link_identifier = @link_identifier, $base_dn = @base_dn, $filter = @filter, $attributes = @attributes, $attrsonly = @attrsonly, $sizelimit = @sizelimit, $timelimit = @timelimit, $deref = @deref) returns @return';
      $variables = array(
        '@link_identifier' => print_r($link_identifier, TRUE),
        '@base_dn' => print_r($base_dn, TRUE),
        '@filter' => print_r($filter, TRUE),
        '@attributes' => print_r($attributes, TRUE),
        '@attrsonly' => print_r($attrsonly, TRUE),
        '@sizelimit' => print_r($sizelimit, TRUE),
        '@timelimit' => print_r($timelimit, TRUE),
        '@deref' => print_r($deref, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return === FALSE) {
      throw new SimpleLdapException($link_identifier);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_set_option().
   *
   * @param resource $link_identifier
   *   An LDAP link identifier.
   * @param int $option
   *   The parameter option.
   *   @see http://us2.php.net/manual/en/function.ldap-set-option.php
   * @param mixed $newval
   *   The new value for the specified option.
   *
   * @return boolean
   *   TRUE on success.
   *
   * @throw SimpleLdapException
   */
  protected static function ldap_set_option($link_identifier, $option, $newval) {
    // Wrapped function call.
    $return = @ldap_set_option($link_identifier, $option, $newval);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link_identifier = @link_identifier, $option = @option, $newval = @newval) returns @return';
      $variables = array(
        '@link_identifier' => print_r($link_identifier, TRUE),
        '@option' => print_r($option, TRUE),
        '@newval' => print_r($newval, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if (!$return) {
      throw new SimpleLdapException($link_identifier);
    }

    return $return;
  }

  /**
   * Wrapper function for ldap_start_tls().
   *
   * @param resource $link
   *   An LDAP link identifier.
   *
   * @return boolean
   *   TRUE on success.
   *
   * @throw SimpleLdapException
   */
  protected static function ldap_start_tls($link) {
    // Wrapped function call.
    $return = @ldap_start_tls($link);

    // Debugging.
    if (variable_get('simple_ldap_debug', FALSE)) {
      $message = __FUNCTION__ . '($link = @link) returns @return';
      $variables = array(
        '@link' => print_r($link, TRUE),
        '@return' => print_r($return, TRUE),
      );
      watchdog('simple_ldap', $message, $variables, WATCHDOG_DEBUG);
    }

    // Error handling.
    if ($return === FALSE) {
      throw new SimpleLdapException($link);
    }

    return $return;
  }

}
