TODO
====
@todo Investigate the use of 'value' in field API.

SimpleLdapUser fingerprint
==========================

// Variables exposed by __get() and __set()
$attributes 
$dn
$exists
$server

// Magic methods
__construct($name)
__destruct()
__get($name)
__set($name, $value)

// Public functions
authenticate($password)
save()
delete()

// Public static methods
singleton($name)
filter()
reset()
hash($key, $value)
