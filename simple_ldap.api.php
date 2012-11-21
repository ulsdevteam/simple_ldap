<?php
/**
 * @file
 * Describe hooks provided by the Simple LDAP User module.
 */

/**
 * SimpleLdapServer Fingerprint.
 *
 * Variables exposed by __get() and __set()
 * ----------------------------------------
 * $host
 * $port
 * $starttls
 * $version
 * $binddn
 * $bindpw
 * $pagesize
 * $readonly
 *
 * Dynamically loaded in __get()
 * -----------------------------
 * $error
 * $rootdse
 * $[sub]schema
 *
 * Static functions
 * ----------------
 * SimpleLdapServer::singleton($reset = FALSE)
 *
 * Magic functions
 * ---------------
 * __construct()
 * __destruct()
 * __get($name)
 * __set($name, $value)
 *
 * Control functions
 * -----------------
 * bind($binddn = null, $bindpw = null)
 * unbind()
 *
 * Read functions
 * --------------
 * search($base_dn, $filter, $scope = 'sub', $attributes = array(),
 *        $attrsonly = 0, $sizelimit = 0, $timelimit = 0,
 *        $deref = LDAP_DEREF_NEVER)
 * exists($dn)
 * entry($dn)
 * compare($dn, $attribute, $value)
 *
 * Write functions
 * ---------------
 * add($dn, $attributes)
 * delete($dn, $recursive = false)
 * modify($dn, $attributes, $type = FALSE)
 * move($dn, $newdn)
 * copy($dn, $newdn)
 *
 * Utility functions
 * -----------------
 * utf8encode($attributes)
 * utf8decode($attributes)
 * clean($entry)
 *
 * Private functions
 * -----------------
 * connect()
 * disconnect()
 * rootdse()
 * schema()
 */

/**
 * SimpleLdapSchema Fingerprint.
 *
 * Variables exposed by __get() and __set()
 * ----------------------------------------
 * $attributes
 * $dn
 *
 * Dynamically loaded in __get()
 * -----------------------------
 * $[sub]entry
 *
 * Magic functions
 * ---------------
 * __construct(SimpleLdapServer $server)
 * __get($name)
 * __set($name, $value)
 *
 * Query functions
 * ---------------
 * exists($attribute, $name = NULL)
 * get($attribute = NULL, $name = NULL)
 *
 * ObjectClass functions
 * ---------------------
 * attributes($objectclass, $recursive = FALSE)
 * may($objectclass, $recursive = FALSE)
 * must($objectclass, $recursive = FALSE)
 * superclass($objectclass, $recursive = FALSE)
 *
 * Potential candidates for future implementation
 * ----------------------------------------------
 * isBinary($attribute)
 * getAssignedOCL($attribute)
 * checkAttribute($attribute, $objectclasses)
 */
