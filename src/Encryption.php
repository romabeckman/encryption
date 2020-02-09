<?php

namespace Encryption;

use \Encryption\Exceptions\FailDecryptException;

class Encryption
{

    private $key;
    private $keyHMAC;
    private $cipher;
    private $cipherHMAC;

    function __construct(string $key, string $keykeyHMAC, string $cipher = 'aes-256-cbc', string $cipherHMAC = 'sha384')
    {
        $this->key = $key;
        $this->keyHMAC = $keykeyHMAC;
        $this->cipher = $cipher;
        $this->cipherHMAC = $cipherHMAC;
    }

    private function getKey(): string
    {
        return $this->key;
    }

    private function getKeyHMAC(): string
    {
        return $this->keyHMAC;
    }

    function getCipher(): string
    {
        return $this->cipher;
    }

    function getCipherHMAC(): string
    {
        return $this->cipherHMAC;
    }

    static public function validateCipherHMAC($cipherHMAC): void
    {
        if (!isset(array_flip(hash_hmac_algos())[$cipherHMAC])) {
            throw new \InvalidArgumentException("Cipher not valid to HMAC");
        }
    }

    static public function validateCipher(string $cipher): void
    {
        if (!isset(array_flip(openssl_get_cipher_methods())[$cipher])) {
            throw new \InvalidArgumentException("Cipher not valid");
        }
    }

    static public function encrypt(self $Encryption, string $text): string
    {
        static::validateCipher($Encryption->getCipher());
        static::validateCipherHMAC($Encryption->getCipherHMAC());

        $IV = random_bytes(openssl_cipher_iv_length($Encryption->getCipher()));

        $textEncrypt = openssl_encrypt($text, $Encryption->getCipher(), $Encryption->getKey(), OPENSSL_RAW_DATA, $IV);
        $textHMAC = hash_hmac($Encryption->getCipherHMAC(), $IV . $textEncrypt, $Encryption->getKeyHMAC(), true);
        return base64_encode($textHMAC . $IV . $textEncrypt);
    }

    static function decrypt(self $Encryption, string $token): string
    {
        static::validateCipher($Encryption->getCipher());
        static::validateCipherHMAC($Encryption->getCipherHMAC());

        $token = base64_decode($token);

        $textHMAC = mb_substr($token, 0, 48, '8bit');
        $IV = mb_substr($token, 48, openssl_cipher_iv_length($Encryption->getCipher()), '8bit');
        $textEncrypt = mb_substr($token, 48 + openssl_cipher_iv_length($Encryption->getCipher()), null, '8bit');

        if (!hash_equals(hash_hmac($Encryption->getCipherHMAC(), $IV . $textEncrypt, $Encryption->getKeyHMAC(), true), $textHMAC)) {
            throw new FailDecryptException('Token is not equal that was generated.');
        }

        $text = openssl_decrypt($textEncrypt, $Encryption->getCipher(), $Encryption->getKey(), OPENSSL_RAW_DATA, $IV);

        if (empty($text))
            throw new FailDecryptException('Token cannot be decrypted. Check encrypt key.');

        return $text;
    }

}
