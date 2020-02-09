# Encryption

- Require php 7.4
- Require composer

## Encrypt/Decrypt example

```
require './vendor/autoload.php';

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
```

## JWT
- data: Data of token
- jti: ID of token
- iss: The domain of the token-generating application
- sub: It is the subject of the token, but it is widely used to store the user ID
- aud: Defines who can use the token
- exp: Token expiration date
- iat: Token creation date
- nbf: Defines a date for which the token cannot be accepted before it


### Example
```
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

```
