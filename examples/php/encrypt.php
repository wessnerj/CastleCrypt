<?php
require_once('CastleCrypt.php');

// Not recommended, provide your own IV!
$cc = new CastleCrypt();

// Load public key
$cc->setPublicKey(file_get_contents('../scripts/test_publicKey.pem'));

// Bytes to encrypt
$data = 'Short Example.';

// Encrypt
$encrypted = $cc->encrypt($data);

// Save to file
file_put_contents('testfile_short', $encrypted);

// Longer example
$data = 'Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.';
// Encrypt
$encrypted = $cc->encrypt($data);
// Save to file
file_put_contents('testfile_longer', $encrypted);
