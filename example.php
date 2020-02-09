<?php

require './vendor/autoload.php';

use \Encryption\Encryption;
use \Encryption\JSONWebToken;

// JSONWebToken::$compareIss = false; //Set false to disable auto-comparison with Domain. Default True.
// JSONWebToken::$defaultExpiration = null; //Set null to disable date expiration or add param in __constructor. Default '2 hours'.

$Encryption = new Encryption('__ENCRYPT_KEY__', '__SECURITY_KEY__');

$JSONWebToken = new JSONWebToken(
        ['nome' => 'Firstname Lastname', 'email' => 'my_email@email.com']
);
$JSONWebToken
        ->setJti(1)
        ->setSub('My Teste')
        ->setAud('Username');

$jwt = JSONWebToken::encode($Encryption, $JSONWebToken);
//$jwt = JSONWebToken::encode($Encryption, $JSONWebToken, true); // To get token for use in url

echo $jwt;

echo '<hr>';

$decoded = JSONWebToken::decode($Encryption, $jwt);
print_r($decoded);

