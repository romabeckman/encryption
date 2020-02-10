# Encryption

- Require php 7.1
- composer require romabeckman/encryption

### Examples:

- Example1: Encrypt and decrypt content adding signature
- Example2: Encrypt and decrypt payload adding signature
- Example3: JWT Token


## Some examples

Simple to encrypte and decrypt a text:

``` 
$encryption = new Encryption("__ENCRYPT_KEY__", "__SECURITY_KEY__");
$hash = Encryption::encrypt($Encryption, 'My text to example'); 
echo Encryption::decrypt($Encryption, $hash);
// must print 'My text to example'
```

You may encrypt only Payload without [RFC 7519 (JWT)](https://tools.ietf.org/html/rfc7519) method. Some reasons, you need encrypt only Payload and transmite by insecurity way. See example:

``` 
$encryption = new Encryption("__ENCRYPT_KEY__", "__SECURITY_KEY__"); 
$Payload = new Payload(
   ['name' => 'Firstname Lastname', 'email' => 'my_email@email.com'], // must encrypt
   strtotime('2 hours') // expiration time
);
// Optional attributes
$Payload
   ->setJti(1)
   ->setSub('My Teste')
   ->setCheckIssDomain(true) // Default false. If true, will set 'iss' like http://my_host.com and check when encoded
   ->setAud('Username');
$token = Payload::encode($Encryption, $Payload);
//$token = Payload::encode($Encryption, $Payload, true); // To get token for use in url

$decoded = Payload::decode($Encryption, $token);
//$decoded = Payload::decode($Encryption, $token, true); // To get token for use in url
```

Generate JWT token conform [RFC 7519 (JWT)](https://tools.ietf.org/html/rfc7519) method:
```
$Encryption = new Encryption('__ENCRYPT_KEY__', '__SECURITY_KEY__');
$Payload = new Payload(
        ['nome' => 'Firstname Lastname', 'email' => 'my_email@email.com'],
        strtotime('2 hours')
);
$jwt = Jwt::encode($Encryption, $Payload);
$decoded = Jwt::decode($Encryption, $jwt);
```
