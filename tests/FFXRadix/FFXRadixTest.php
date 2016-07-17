<?php
namespace Janv\FFXRadix\Tests;

use Janv\FFXRadix\FFXRadix;

class FFXRadixTest extends \PHPUnit_Framework_TestCase
{
    public function test()
    {
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $tests = [
            // http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt
            ['9876543210', '0123456789', '6124200773', 10],
            ['', '0123456789', '2433477484', 10],
            ['2718281828', '314159', '535005', 10],
            ['7777777', '999999999', '658229573', 10],
            // The input and output must be lowercase to be within the radix=36 alphabet: 0-9a-z
            // It also shows that tweak is just raw bytes and thus its character could be outside the radix=36 alphabet
            ['TQF9J5QDAGSCSPB1', 'c4xpwulbm3m863jh', 'c8aq3u846zwh6qzp', 36],

            // Other tests
            // Test 'Y expansion' (input range > 8^24)
            ['', '0000000000000000000000000000000000000000000000000', '80a5d84e29d517ed24d38a6e0aba502dc457a56880ffa58eb', 16],
            // Test empty string
            ['', '', '', 2],
        ];

        $ffx = new FFXRadix();

        foreach ($tests as $row) {
            $input = $row[1];
            $radix = $row[3];
            $tweak = $row[0];
            $output = $row[2];

            $enc = $ffx->encrypt($input, $radix, $key, $tweak);
            $this->assertSame($output, $enc);
            $dec = $ffx->decrypt($enc, $radix, $key, $tweak);
            $this->assertSame($input, $dec);
        }
    }
}
