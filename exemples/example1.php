<?php

require '../vendor/autoload.php';

use \Encryption\Encryption;

$text = "My text to encrypt";

$key = "__ENCRYPT_KEY__"; // encrypt or decrypt key
$securitykey = "__SECURITY_KEY__"; // compare and validate encrypted token
$cipher = "aes-256-cbc"; // see openssl_get_cipher_methods()
$cipherHMAC = "sha384"; // see hash_hmac_algos()

$Encryption = new Encryption($key, $securitykey, $cipher, $cipherHMAC);

$token = Encryption::encrypt($Encryption, $text);
echo $token;
echo "<hr>";
$textDecrypted = Encryption::decrypt($Encryption, $token);
echo $textDecrypted; // will print "My text to encrypt"