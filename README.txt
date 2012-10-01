README.txt
==========

SimpleLdapServer
================

$host
$port
$starttls
$version
$binddn
$bindpw

// Load these in __get()
$rootdse
$schema

SimpleLdapServer::singleton($reset = FALSE)

__construct()
__destruct()
__get($name)
__set($name, $value)

bind($binddn = null, $bindpw = null)
unbind()

search($base_dn, $filter, $scope = 'sub', $attributes = array(),
       $attrsonly = 0, $sizelimit = 0, $timelimit = 0,
       $deref = LDAP_DEREF_NEVER)

exists($dn)
add($dn, $attributes)
delete($dn, $recursive = false)
modify($dn, $attributes)

error()

*move($dn, $newdn)
*copy($dn, $newdn)
*utf8encode($attributes)
*utf8decode($attributes)
*getOption($option)
*setOption($option, $value)

_connect()
_disconnect()
_rootdse()
_schema()
_clean($entry)


SimpleLdapSchema
================

$attributes
$dn

__construct(SimpleLdapServer $server)
__get($name)
__set($name, $value)

exists($attribute, $name = NULL)
get($attribute = NULL, $name = NULL)

may($objectclass, $recursive = FALSE)
must($objectclass, $recursive = FALSE)
superclass($objectclass, $recursive = FALSE)

*isBinary($attribute)
*getAssignedOCL($attribute)
*checkAttribute($attribute, $objectclasses)
