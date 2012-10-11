README.txt
==========

Back of the napkin:

- Override Drupal's user management, and force LDAP to be the source of
  information (except for user:1)
- If the given binddn does not have permission to create/modify entries, user
  management via drupal is disabled
- Assume information in LDAP is authoratative, and overwrite drupal info.
- When a drupal account that has no matching LDAP account is accessed, attempt
  to create the LDAP account.  If it fails, deny access.
- Provision new LDAP accounts when a Drupal account is set to "active"
- Handle password reset and account registration
- Nested groups are not supported

SimpleLdapServer Fingerprint
============================

// Variables exposed by __get() and __set()
$host
$port
$starttls
$version
$binddn
$bindpw
$pagesize
$readonly

// Dynamically loaded in __get()
$error
$rootdse
$[sub]schema

// Static functions
SimpleLdapServer::singleton($reset = FALSE)

// Magic functions
__construct()
__destruct()
__get($name)
__set($name, $value)

// Control functions
bind($binddn = null, $bindpw = null)
unbind()

// Read functions
search($base_dn, $filter, $scope = 'sub', $attributes = array(),
       $attrsonly = 0, $sizelimit = 0, $timelimit = 0,
       $deref = LDAP_DEREF_NEVER)
exists($dn)
entry($dn)
compare($dn, $attribute, $value)

// Write functions
add($dn, $attributes)
delete($dn, $recursive = false)
modify($dn, $attributes)
move($dn, $newdn)
copy($dn, $newdn)

// Utility functions
utf8encode($attributes)
utf8decode($attributes)

// Private functions
clean($entry)
connect()
disconnect()
rootdse()
schema()


SimpleLdapSchema Fingerprint
============================

// Variables exposed by __get() and __set()
$attributes
$dn

// Dynamically loaded in __get()
$[sub]entry

// Magic functions
__construct(SimpleLdapServer $server)
__get($name)
__set($name, $value)

// Query functions
exists($attribute, $name = NULL)
get($attribute = NULL, $name = NULL)

// ObjectClass functions
attributes($objectclass, $recursive = FALSE)
may($objectclass, $recursive = FALSE)
must($objectclass, $recursive = FALSE)
superclass($objectclass, $recursive = FALSE)

// Potential candidates for future implementation
isBinary($attribute)
getAssignedOCL($attribute)
checkAttribute($attribute, $objectclasses)
