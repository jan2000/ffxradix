<?php
require __DIR__.'/vendor/autoload.php';

use Janv\FFXRadix\FFXRadix;

// Key must be a 16 byte long string if AES-128 (default) is used
$key = hex2bin('00000000000000000000000000000000');
// Tweak can be anything
$tweak = hex2bin('0123456789abcdef');

$ffx = new FFXRadix();

// Encrypt a 16 decimal number (radix = 10)
$enc = $ffx->encrypt(sprintf('%016d', 1), 10, $key, $tweak);
// Outputs 1299047952447293
echo "$enc\n";

// Decrypt
$dec = $ffx->decrypt($enc, 10, $key, $tweak);
// Outputs 0000000000000001
echo "$dec\n";
