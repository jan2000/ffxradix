<?php
namespace Janv\FFXRadix;

// For PHP < 5.6.1
if (!function_exists('\gmp_import')) {
    function gmp_import ($data, $word_size = 1, $options = 17)
    {
        return gmp_init(bin2hex($data), 16);
    }
}
if (!function_exists('\gmp_export')) {
    function gmp_export ($gmpnumber, $word_size = 1, $options = 17)
    {
        $str = gmp_strval($gmpnumber, 16);
        return hex2bin((strlen($str) & 1 ? '0' : '') . $str);
    }
}

/**
 * Class FFXRadix
 * @package Janv\FFXRadix
 * @author jan@venekamp.net
 *
 * Implementation of "The Scheme FFX[radix]" as described in "The FFX Mode of Operation for Format-Preserving Encryption"
 *
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec2.pdf
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec.pdf
 */
class FFXRadix
{
    /**
     * Encrypt data using format-preserving encryption
     * @param string $input The plaintext data
     * @param integer $radix The radix of the data, must be in the range 2-62
     * @param string $key The key to use for encryption (raw bytes)
     * @param string $tweak Tweak data (raw bytes)
     * @return string The encrypted data
     */
    public function encrypt($input, $radix, $key, $tweak = '')
    {
        if (strlen($key) != 16) throw new \InvalidArgumentException('$key must be a string of 16 bytes');
        return $this->crypt(true, $key, $tweak, $input, $radix);
    }

    /**
     * Decrypt data using format-preserving encryption
     * @param string $input The encrypted data
     * @param integer $radix The radix of the data, must be in the range 2-62
     * @param string $key The key used for encryption (raw bytes)
     * @param string $tweak Tweak data (raw bytes)
     * @return string The plaintext data
     */
    public function decrypt($input, $radix, $key, $tweak = '')
    {
        if (strlen($key) != 16) throw new \InvalidArgumentException('$key must be a string of 16 bytes');
        return $this->crypt(false, $key, $tweak, $input, $radix);
    }

    // Names of variables below are kept as close as possible to the description in the paper

    protected function crypt($encrypt, $K, $T, $X, $radix)
    {
        $n = strlen($X);
        $l = floor($n/2); // balanced split
        $r = 10; // Always use 10 rounds

        if ($n < 1) return '';

        // This is taken out of the round function
        // P is static and thus its CBC-MAC can be precomputed and used as IV
        $P = "\x01". // VERS = 1
            "\x02". // method
            "\x01". // addition
            "\x00\x00".chr($radix). // radix3
            "\x0A". // rnds
            chr(floor($n/2)).
            $this->fixedLength(gmp_export(gmp_init($n)), 4). // n4
            $this->fixedLength(gmp_export(gmp_init(strlen($T))), 4)  // t4
        ;
        $iv = openssl_encrypt($P, 'AES-128-ECB', $K, \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING);

        $A = substr($X, 0, $l);
        $B = substr($X, $l);

        if ($encrypt) {
            for ($i = 0; $i < $r; $i++) {
                $C = $this->addition($A, $this->round($K, $n, $T, $i, $B, $iv, $radix), $radix);
                $A = $B;
                $B = $C;
            }
        } else {
            for ($i = $r - 1; $i >= 0; $i--) {
                $C = $B;
                $B = $A;
                $A = $this->subtraction($C, $this->round($K, $n, $T, $i, $B, $iv, $radix), $radix);
            }
        }

        return $A.$B;
    }

    protected function round($K, $n, $T, $i, $B, $iv, $radix)
    {
        // $b is the length of the input when converted to radix=256, thus num of bytes (rounded)
        $b = (int) ceil(ceil(ceil($n/2) * log($radix, 2)) / 8);
        $d = (int) (4 * ceil($b / 4));

        // Input
        $Q = $T .
            str_repeat("\x00", (-strlen($T) - $b -1) & 0xF). // padding of Q to multiple of 16 bytes
            chr($i).
            $this->fixedLength(gmp_export(gmp_init($B, $radix)), $b) // [ NUM_radix(B) ]b (data in bytes)
        ;

        // Y = CBC-MAC_K(P·Q)
        // CBC-MAC is the same as the last block of cipher text of CBC mode and a zero iv (the iv used here is P')
        $Y = substr(openssl_encrypt($Q, 'AES-128-CBC', $K, \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING, $iv), -16);
        // Y = first d + 4 bytes of (Y · AES_K(Y ⊕ [1]16) · AES_K(Y ⊕ [2]16) · AES_K(Y ⊕ [3]16)·· )
        $E = '';
        for ($j = 1; $j * 16 < $d + 4; $j++) {
            $J = $this->fixedLength(gmp_export(gmp_init($j)), 16);
            $E .= openssl_encrypt($Y ^ $J, 'AES-128-ECB', $K, \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING);
        }
        $Y = substr($Y.$E, 0, $d+4);

        // y = NUM_2(Y)
        $y = gmp_import($Y);

        $m = (int) (($i & 1) ? ceil($n/2) : floor($n/2));
        // z = y mod radix^m is actually cropping the string length
        return $this->fixedLength(gmp_strval($y, $radix), $m, '0');
    }

    protected function addition($A, $B, $radix)
    {
        $a = gmp_init($A, $radix);
        $b = gmp_init($B, $radix);
        // Block-wise addition
        return $this->fixedLength(gmp_strval(gmp_add($a, $b), $radix), strlen($A), '0');
    }

    protected function subtraction($A, $B, $radix)
    {
        $a = gmp_init($A, $radix);
        $b = gmp_init($B, $radix);
        // Prevent negative values
        if (gmp_cmp($a, $b) < 0) $a = gmp_add($a, gmp_pow($radix, strlen($A)));
        // Block-wise subtraction
        return $this->fixedLength(gmp_strval(gmp_sub($a, $b), $radix), strlen($A), '0');
    }

    protected function fixedLength($string, $length, $pad = "\x00")
    {
        return $length > 0 ? substr(str_pad($string, $length, $pad, \STR_PAD_LEFT), -$length) : '';
    }
}
