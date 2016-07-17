<?php
namespace Janv\FFXRadix\Tests;

use Janv\FFXRadix\FFXRadix;

class FFXRadixTest extends \PHPUnit_Framework_TestCase
{
    public function test()
    {
        $full_key = hex2bin('2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f7f036d6f04fc6a94');
        $tests = [
            // http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf
            ['AES-128','','0123456789','2433477484',10],
            ['AES-128','9876543210','0123456789','6124200773',10],
            ['AES-128','7777pqrs777','0123456789abcdefghi','a9tv40mll9kdu509eum',36],
            ['AES-192','','0123456789','2830668132',10],
            ['AES-192','9876543210','0123456789','2496655549',10],
            ['AES-192','7777pqrs777','0123456789abcdefghi','xbj3kv35jrawxv32ysr',36],
            ['AES-256','','0123456789','6657667009',10],
            ['AES-256','9876543210','0123456789','1001623463',10],
            ['AES-256','7777pqrs777','0123456789abcdefghi','xs8a0azh2avyalyzuwd',36],

            // http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt
            ['AES-128','2718281828', '314159', '535005', 10],
            ['AES-128','7777777', '999999999', '658229573', 10],
            // The input and output must be lowercase to be within the radix=36 alphabet: 0-9a-z
            // It also shows that tweak is just raw bytes and thus its character could be outside the radix=36 alphabet
            ['AES-128','TQF9J5QDAGSCSPB1', 'c4xpwulbm3m863jh', 'c8aq3u846zwh6qzp', 36],

            // Other tests
            // Test 'Y expansion' (input range > 8^24)
            ['AES-128','', '0000000000000000000000000000000000000000000000000', '80a5d84e29d517ed24d38a6e0aba502dc457a56880ffa58eb', 16],
            // Test empty string
            ['AES-128','', '', '', 2],
        ];

        $ffx = new FFXRadix();

        foreach ($tests as $row) {
            $cipher = $row[0];
            $input = $row[2];
            $radix = $row[4];
            $tweak = $row[1];
            $output = $row[3];

            $ffx->setCipher($cipher);
            $key = substr($full_key, 0, substr($cipher, -3) / 8);

            $enc = $ffx->encrypt($input, $radix, $key, $tweak);
            $this->assertSame($output, $enc);
            $dec = $ffx->decrypt($enc, $radix, $key, $tweak);
            $this->assertSame($input, $dec);
        }
    }
}
