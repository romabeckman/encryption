<?php

require '../vendor/autoload.php';

use \Encryption\Encryption;
use \Encryption\Payload;
use \Encryption\Jwt;

$Encryption = new Encryption('__ENCRYPT_KEY__', '__SECURITY_KEY__');

$Payload = new Payload(
        ['nome' => 'Firstname Lastname', 'email' => 'my_email@email.com'],
        strtotime('2 hours')
);
$Payload
        ->setJti(1)
        ->setSub('My Teste')
        ->setAud('Username');

$jwt = Jwt::encode($Encryption, $Payload);

echo $jwt;

echo '<hr>';

$decoded = Jwt::decode($Encryption, $jwt);
print_r($decoded);
