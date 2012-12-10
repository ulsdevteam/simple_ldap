<?php
/**
 * @file
 * Class defining base Simple LDAP functionallity.
 */

/**
 * Simple LDAP class.
 */
class SimpleLdap {

  /**
   * UTF8-encode an attribute or array of attributes.
   */
  public static function utf8encode($attributes) {
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
  public static function utf8decode($attributes) {
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
   * Generates a random salt of the given length.
   */
  public static function salt($length) {
    $possible = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./';
    $str = '';

    mt_srand((double) microtime() * 1000000);
    while (strlen($str) < $length) {
      $str .= substr($possible, (rand() % strlen($possible)), 1);
    }

    return $str;
  }

  /**
   * Hash a string for use in an LDAP password field.
   */
  public static function hash($string, $algorithm = NULL) {
    switch ($algorithm) {
      case 'crypt':
        $hash = '{CRYPT}' . crypt($string, substr($string, 0, 2));
        break;

      case 'salted crypt':
        $hash = '{CRYPT}' . crypt($string, self::salt(2));
        break;

      case 'extended des':
        $hash = '{CRYPT}' . crypt($string, '_' . self::salt(8));
        break;

      case 'md5crypt':
        $hash = '{CRYPT}' . crypt($string, '$1$' . self::salt(9));
        break;

      case 'blowfish':
        $hash = '{CRYPT}' . crypt($string, '$2a$12$' . self::salt(13));
        break;

      case 'md5':
        $hash = '{MD5}' . base64_encode(pack('H*', md5($string)));
        break;

      case 'salted md5':
        mt_srand((double) microtime() * 1000000);
        $salt = mhash_keygen_s2k(MHASH_MD5, $string, substr(pack('h*', md5(mt_rand())), 0, 8), 4);
        $hash = '{SMD5}' . base64_encode(mhash(MHASH_MD5, $string . $salt) . $salt);
        break;

      case 'sha':
        $hash = '{SHA}' . base64_encode(pack('H*', sha1($string)));
        break;

      case 'salted sha':
        mt_srand((double) microtime() * 1000000);
        $salt = mhash_keygen_s2k(MHASH_SHA1, $string, substr(pack('h*', md5(mt_rand())), 0, 8), 4);
        $hash = '{SSHA}' . base64_encode(mhash(MHASH_SHA1, $string . $salt) . $salt);
        break;

      case 'unicode':
        $string = '"' . $string . '"';
        $length = drupal_strlen($string);
        $hash = '';
        for ($i = 0; $i < $length; $i++) {
          $hash .= "{$string{$i}}\000";
        }
        break;

      case 'none':
      default:
        $hash = $string;
    }

    return $hash;
  }

  /**
   * Returns an array of supported hash types.
   *
   * The keys of this array are also the values supported by SimpleLdap::hash().
   * The values are translated, human-readable values.
   */
  public static function hashes() {
    $types = array();

    // Crypt, and Salted Crypt.
    $types['crypt'] = t('Crypt');
    $types['salted crypt'] = t('Salted Crypt');

    // Extended DES.
    if (defined('CRYPT_EXT_DES') || CRYPT_EXT_DES == 1) {
      $types['extended des'] = t('Extended DES');
    }

    // MD5Crypt.
    if (defined('CRYPT_MD5') || CRYPT_MD5 == 1) {
      $types['md5crypt'] = t('MD5Crypt');
    }

    // Blowfish.
    if (defined('CRYPT_BLOWFISH') || CRYPT_BLOWFISH == 1) {
      $types['blowfish'] = t('Blowfish');
    }

    // MD5
    $types['md5'] = t('MD5');

    // SMD5.
    if (function_exists('mhash') && function_exists('mhash_keygen_s2k')) {
      $types['salted md5'] = t('Salted MD5');
    }

    // SHA.
    $types['sha'] = t('SHA');

    // SSHA.
    if (function_exists('mhash') && function_exists('mhash_keygen_s2k')) {
      $types['salted sha'] = t('Salted SHA');
    }

    // Unicode (used by Active Directory).
    $types['unicode'] = t('Unicode');

    return $types;
  }

}
