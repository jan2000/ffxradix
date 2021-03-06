FFXRadix
========

[![Build Status](https://travis-ci.org/jan2000/ffxradix.svg?branch=master)](https://travis-ci.org/jan2000/ffxradix)

A PHP implementation of the FFX\[radix\] Scheme of *The FFX Mode of Operation for Format-Preserving Encryption*[1,2].
Also known as mode FF1 in NIST Special Publication 800-38G:
*Recommendation for Block Cipher Modes of Operation: Methods for Format-Preserving Encryption*[3]

Encrypt and decrypt a message with a radix between 2 to 62 and preserves its length. Messages to be enciphered under
FFX\[radix\] are regarded as strings of characters drawn from the alphabet `Chars = {0, 1, 2,...,radix − 1}`.
Scheme FFX\[radix\] does its work using an AES-based balanced Feistel network. If the message length is odd, an
alternating, maximally-balanced Feistel scheme is used instead.

* [1] http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec.pdf
* [2] http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec2.pdf
* [3] http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf

Example Usage
-------------

```php
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
```

Testing
-------

This implementation is validated against the test vectors provided in:
* http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt
* http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/FF1samples.pdf