<?php
/**
 * @file
 * Class to represent an LDAP server schema.
 */

/**
 * Simple LDAP Schema class.
 */
class SimpleLdapSchema {

  protected $dn;
  protected $schema;
  protected $server;
  protected $attributes = array(
    'attributeTypes',
    'dITContentRules',
    'dITStructureRules',
    'matchingRules',
    'matchingRuleUse',
    'nameForms',
    'objectClasses',
    'ldapSyntaxes',
  );

  /**
   * Constructor.
   */
  public function __construct(SimpleLdapServer $server) {
    $this->server = $server;

    if (isset($this->server->rootdse['subschemasubentry'])) {
      $this->dn = $this->server->rootdse['subschemasubentry'][0];
    }
    else {
      // Fallback for broken servers.
      $this->dn = 'cn=Subschema';
    }

  }

  /**
   * Magic __get function.
   *
   * @todo Get entire schema array -- be sure the whole thing is loaded.
   */
  public function __get($name) {
    switch ($name) {
      case 'dn':
      case 'attributes':
        return $this->$name;
        break;
    }
  }

  /**
   * Magic __set function.
   */
  public function __set($name, $value) {
    // The schema is read-only, just return.
    return;
  }

  /**
   * Returns whether the given item exists.
   *
   * @todo Rename $type to $attribute.
   * @todo Support oid as well as attribute name
   */
  public function exists($type, $name = NULL) {
    // Make sure the schema for the requested type is loaded.
    $this->load(array($type));

    // Check to see if the requested schema entry exists.
    $type = strtolower($type);
    if (isset($this->schema[$type])) {
      if ($name === NULL) {
        return (count($this->schema[$type]) > 0);
      }
      else {
        return isset($this->schema[$type][strtolower($name)]);
      }
    }

    return FALSE;
  }

  /**
   * Fetches entries of the given type.
   *
   * @param string $name
   *   If specified, a single entry with this name is returned.
   *
   * @todo Rename $type to $attribute.
   * @todo Support oid as well as name.
   * @todo Handle an array of attributes, as well as default to all attributes.
   */
  public function get($type, $name = NULL) {
    if ($this->exists($type, $name)) {
      if ($name === NULL) {
        return $this->schema[strtolower($type)];
      }
      else {
        return $this->schema[strtolower($type)][strtolower($name)];
      }
    }

    return FALSE;
  }

  /**
   * Return a list of attributes specified as MAY for the objectclass.
   */
  public function may($objectclass, $recursive = FALSE) {
    if ($oc = $this->get('objectclasses', $objectclass)) {
      $may = array();

      if (isset($oc['may'])) {
        $may = $oc['may'];
      }

      if ($recursive && isset($oc['sup'])) {
        foreach ($oc['sup'] as $sup) {
          $may = array_merge($may, $this->may($sup, TRUE));
        }
      }

      return $may;
    }

    return FALSE;
  }

  /**
   * Return a list of attributes specified as MUST for the objectclass.
   */
  public function must($objectclass, $recursive = FALSE) {
    if ($oc = $this->get('objectclasses', $objectclass)) {
      $must = array();

      if (isset($oc['must'])) {
        $must = $oc['must'];
      }

      if ($recursive && isset($oc['sup'])) {
        foreach ($oc['sup'] as $sup) {
          $must = array_merge($must, $this->must($sup, TRUE));
        }
      }

      return $must;
    }

    return FALSE;
  }

  /**
   * Returns the objectclass's superclass.
   */
  public function superclass($objectclass, $recursive = FALSE) {
    if ($oc = $this->get('objectclasses', $objectclass)) {
      $superclass = array();

      if (isset($oc['sup'])) {
        $superclass = $oc['sup'];
        if ($recursive) {
          foreach ($oc['sup'] as $sup) {
            $superclass = array_merge($superclass, $this->superclass($sup, TRUE));
          }
        }
      }

      return $superclass;
    }

    return FALSE;
  }

  /**
   * Load the schema.
   *
   * Schema parsing can be slow, so only the attributes that are specified, and
   * are not already cached, are loaded.
   */
  protected function load($attributes = NULL) {
    if ($attributes === NULL) {
      $attributes = $this->attributes;
    }

    // Determine which attributes need to be loaded.
    $load = array();
    foreach ($attributes as $attribute) {
      $attribute = strtolower($attribute);
      if (!isset($this->schema[$attribute])) {
        $load[] = $attribute;
      }
    }

    if (!empty($load)) {
      $result = $this->server->search($this->dn, 'objectclass=*', 'base', $load);

      // Parse the schema.
      foreach ($load as $attribute) {
        $attribute = strtolower($attribute);
        $this->schema[$attribute] = array();

        // Get the values for each attribute.
        if (isset($result[$this->dn][$attribute])) {
          foreach ($result[$this->dn][$attribute] as $value) {
            $parsed = $this->parse($value);
            $this->schema[$attribute][strtolower($parsed['name'])] = $parsed;
          }
        }
      }
    }
  }

  /**
   * Parse a schema value into a usable array.
   *
   * @link
   *   http://pear.php.net/package/Net_LDAP2/
   *
   * @license
   *   http://www.gnu.org/licenses/lgpl-3.0.txt LGPLv3
   */
  protected function parse($value) {
    // Tokens that have no associated value.
    $novalue = array(
      'single-value',
      'obsolete',
      'collective',
      'no-user-modification',
      'abstract',
      'structural',
      'auxiliary',
    );

    // Tokens that can have multiple values.
    $multivalue = array('must', 'may', 'sup');

    // Initialization.
    $schema_entry = array('aliases' => array());

    // Get an array of tokens.
    $tokens = $this->tokenize($value);

    // Remove left paren.
    if ($tokens[0] == '(') {
      array_shift($tokens);
    }

    // Remove right paren.
    if ($tokens[count($tokens) - 1] == ')') {
      array_pop($tokens);
    }

    // The first token is the OID.
    $schema_entry['oid'] = array_shift($tokens);

    // Loop through the tokens until there are none left.
    while (count($tokens) > 0) {
      $token = strtolower(array_shift($tokens));
      if (in_array($token, $novalue)) {
        // Single value token.
        $schema_entry[$token] = 1;
      }
      else {
        // This one follows a string or a list if it is multivalued.
        if (($schema_entry[$token] = array_shift($tokens)) == '(') {
          // This creates the list of values and cycles through the tokens until
          // the end of the list is reached ')'.
          $schema_entry[$token] = array();
          while ($tmp = array_shift($tokens)) {
            if ($tmp == ')') {
              break;
            }
            if ($tmp != '$') {
              array_push($schema_entry[$token], $tmp);
            }
          }
        }
        // Create an array if the value should be multivalued but was not.
        if (in_array($token, $multivalue) && !is_array($schema_entry[$token])) {
          $schema_entry[$token] = array($schema_entry[$token]);
        }
      }
    }

    // Get the max length from syntax.
    if (key_exists('syntax', $schema_entry)) {
      if (preg_match('/{(\d+)}/', $schema_entry['syntax'], $matches)) {
        $schema_entry['max_length'] = $matches[1];
      }
    }

    // Force a name.
    if (empty($schema_entry['name'])) {
      $schema_entry['name'] = $schema_entry['oid'];
    }

    // Make one name the default and put the others into aliases.
    if (is_array($schema_entry['name'])) {
      $aliases = $schema_entry['name'];
      $schema_entry['name'] = array_shift($aliases);
      $schema_entry['aliases'] = $aliases;
    }

    return $schema_entry;
  }

  /**
   * Tokenizes the given value into an array of tokens.
   *
   * @link
   *   http://pear.php.net/package/Net_LDAP2/
   *
   * @license
   *   http://www.gnu.org/licenses/lgpl-3.0.txt LGPLv3
   */
  protected function tokenize($value) {
    $tokens = array();
    $matches = array();

    // This one is taken from perl-lap, modified for php.
    $pattern = "/\s* (?:([()]) | ([^'\s()]+) | '((?:[^']+|'[^\s)])*)') \s*/x";

    // This one matches one big pattern wherin only one of the three subpatterns
    // matched. We are interested in the subpatterns that matched. If it matched
    // its value will be non-empty and so it is a token. Tokens may be round
    // brackets, a string, or a string enclosed by "'".
    preg_match_all($pattern, $value, $matches);

    // Loop through all tokens (full pattern match).
    for ($i = 0; $i < count($matches[0]); $i++) {
      // Loop through each sub-pattern.
      for ($j = 1; $j < 4; $j++) {
        // Pattern match in this sub-pattern.
        $token = trim($matches[$j][$i]);
        if (!empty($token)) {
          $tokens[$i] = $token;
        }
      }
    }

    return $tokens;
  }
}
