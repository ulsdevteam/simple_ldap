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
        $result = @ldap_get_option($this->resource, constant($name), $value);
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
        @ldap_get_option($this->resource, constant($name), $old_value);
        $result = @ldap_set_option($this->resource, constant($name), $value);
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
        $this->bound = @ldap_bind($this->resource, $this->binddn, $this->bindpw);
      }
      else {
        // Bind with the given credentials. This is a temporary bind to verify
        // the password, so $this->bound is reset to FALSE.
        $result = @ldap_bind($this->resource, $binddn, $bindpw);
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
        @ldap_control_paged_result($this->resource, $this->pagesize, FALSE, $cookie);
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

      // Free the query result memory.
      @ldap_free_result($result);

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

    return @ldap_compare($this->resource, $dn, $attribute, $value);
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
    return @ldap_add($this->resource, $dn, $attributes);
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

    return @ldap_delete($this->resource, $dn);
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
        $result = @ldap_mod_add($this->resource, $dn, $attributes);
        break;

      case 'del':
      case 'delete':
        $result = @ldap_mod_del($this->resource, $dn, $attributes);
        break;

      case 'replace':
        $result = @ldap_mod_replace($this->resource, $dn, $attributes);
        break;

      default:
        $result = @ldap_modify($this->resource, $dn, $attributes);
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

    ldap_get_option($this->resource, LDAP_OPT_CLIENT_CONTROLS, $controls);

    $entry = $this->entry($dn);
    if ($entry !== FALSE) {
      $result = $this->add($newdn, $entry[$dn]);
    }

    return FALSE;
  }

  /**
   * UTF8-encode an attribute or array of attributes.
   */
  public function utf8encode($attributes) {
    // $attributes is expected to be an associative array.
    if (!is_array($attributes) || array_key_exists(0, $attributes)) {
      return FALSE;
    }

    // Make sure the schema is loaded.
    $this->schema();

    // Loop through the given attributes.
    $utf8 = array();
    foreach ($attributes as $attribute => $value) {

      // Verify the schema entry for the current attribute is supposed to be
      // utf8 encoded. This is specified by a syntax OID of
      // 1.3.6.1.4.1.1466.115.121.1.15
      $attributetype = $this->schema->get('attributetypes', $attribute);
      if (isset($attributetype['syntax']) && $attributetype['syntax'] == '1.3.6.1.4.1.1466.115.121.1.15') {
        $utf8[$attribute] = utf8_encode($value);
      }
      else {
        $utf8[$attribute] = $value;
      }

    }

    return $utf8;
  }

  /**
   * UTF8-decode an attribute or array of attributes.
   */
  public function utf8decode($attributes) {
    // $attributes is expected to be an associative array.
    if (!is_array($attributes) || array_key_exists(0, $attributes)) {
      return FALSE;
    }

    // Make sure the schema is loaded.
    $this->schema();

    // Loop through the given attributes.
    $utf8 = array();
    foreach ($attributes as $attribute => $value) {

      // Verify the schema entry for the current attribute is supposed to be
      // utf8 encoded. This is specified by a syntax OID of
      // 1.3.6.1.4.1.1466.115.121.1.15
      $attributetype = $this->schema->get('attributetypes', $attribute);
      if (isset($attributetype['syntax']) && $attributetype['syntax'] == '1.3.6.1.4.1.1466.115.121.1.15') {
        $utf8[$attribute] = utf8_decode($value);
      }
      else {
        $utf8[$attribute] = $value;
      }

    }

    // Return the utf8-decoded array.
    return $utf8;
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
      $this->resource = @ldap_connect($this->host, $this->port);
      if ($this->resource === FALSE) {
        return FALSE;
      }

      // Set the LDAP version.
      if (!@ldap_set_option($this->resource, LDAP_OPT_PROTOCOL_VERSION, $this->version)) {
        return FALSE;
      }

      // StartTLS.
      if ($this->starttls) {
        if (!@ldap_start_tls($this->resource)) {
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
  public function directoryType() {
    // Load the rootDSE.
    $this->rootdse();

    // Check for OpenLDAP.
    if (isset($this->rootdse['objectclass']) && is_array($this->rootdse['objectclass'])) {
      if (in_array('OpenLDAProotDSE', $this->rootdse['objectclass'])) {
        return 'OpenLDAP';
      }
    }

    // Check for Active Directory.
    if (isset($this->rootdse['rootdomainnamingcontext'])) {
      return 'Active Directory';
    }

    // Default to generic LDAPv3.
    return 'LDAPv3';
  }

}
