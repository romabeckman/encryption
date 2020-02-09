<?php

class JSONWebToken
{

    private $key;
    private $keyHMAC;
    private $cipher;
    private $cipherHMAC;

    public static $leeway = 0;

    public static $timestamp = null;

    function __construct($key, $keykeyHMAC, $cipher = 'AES-256-CBC', $cipherHMAC = 'SHA384')
    {
        $this->key = $key;
        $this->keyHMAC = $keykeyHMAC;
        $this->cipher = $cipher;
        $this->cipherHMAC = $cipherHMAC;
    }

    public function encode(array $payload, $urlEncode = false):string
    {
        $json = json_encode($payload);
        $token = $this->encrypt($json);
        return $urlEncode ? urlencode($token) : $token;
    }

    public function decode(string $token): array
    {
        $payload = $this->decrypt($token);
        $payload = (array) json_decode($payload);

        if(is_null($payload)) {
            throw new \UnexpectedValueException("Invalid token value");
        }

        $timestamp = is_null(static::$timestamp) ? time() : static::$timestamp;

        if (isset($payload['nbf']) && $payload['nbf'] > ($timestamp + static::$leeway)) {
            throw new \Exception(
                'Cannot handle token prior to ' . date(DateTime::ISO8601, $payload['nbf'])
            );
        }

        if (isset($payload['iat']) && $payload['iat'] > ($timestamp + static::$leeway)) {
            throw new \Exception(
                'Cannot handle token prior to ' . date(DateTime::ISO8601, $payload['iat'])
            );
        }

        // Check if this token has expired.
        if (isset($payload['exp']) && ($timestamp - static::$leeway) >= $payload['exp']) {
            throw new \Exception('Expired token');
        }

        return $payload;
    }

    private function encrypt(string $text): string
    {
        $IV = $this->getIV();
        $textEncrypt = openssl_encrypt($text, $this->cipher, $this->key, OPENSSL_RAW_DATA, $IV);
        $textHMAC = hash_hmac($this->cipherHMAC, $IV . $textEncrypt, $this->keyHMAC, true);
        return base64_encode($textHMAC . $IV . $textEncrypt);
    }

    private function decrypt(string $token): string
    {
        $token = base64_decode($token);
        $textHMAC = mb_substr($token, 0, 48, '8bit');
        $IV = mb_substr($token, 48, openssl_cipher_iv_length($this->cipher), '8bit');
        $textEncrypt = mb_substr($token, 48 + openssl_cipher_iv_length($this->cipher), null, '8bit');

        if (!hash_equals(hash_hmac($this->cipherHMAC, $IV . $textEncrypt, $this->keyHMAC, true), $textHMAC)) {
            throw new \Exception('Token is not valid');
        }

        return openssl_decrypt($textEncrypt, $this->cipher, $this->key, OPENSSL_RAW_DATA, $IV);
    }

    private function getIV(): string
    {
        return random_bytes(openssl_cipher_iv_length($this->cipher));
    }

}
