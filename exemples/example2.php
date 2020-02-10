<?php

require '../vendor/autoload.php';

use \Encryption\Encryption;
use \Encryption\Payload;

// Payload::$compareIss = false; //Set true enable auto-comparison with Domain. Default True.

$Encryption = new Encryption('__ENCRYPT_KEY__', '__SECURITY_KEY__');

$Payload = new Payload(
        ['nome' => 'Firstname Lastname', 'email' => 'my_email@email.com'],
        strtotime('2 hours')
);
$Payload
        ->setJti(1)
        ->setSub('My Teste')
        ->setAud('Username');

$token = Payload::encode($Encryption, $Payload);
//$token = Payload::encode($Encryption, $Payload, true); // To get token for use in url

echo $token;

echo '<hr>';

$decoded = Payload::decode($Encryption, $token);
print_r($decoded);
