<?php
require_once('CastleCrypt.php');

// Not recommended, provide your own IV!
$cc = new CastleCrypt();

// Load private key
$cc->setPrivateKey(file_get_contents('../scripts/test_privateKey.pem'));

// Load encrypted data
$encryptedData = file_get_contents('testfile_short');

// Decrypt
$data = $cc->decrypt($encryptedData);
// print
echo $data . "\n";
