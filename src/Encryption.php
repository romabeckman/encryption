<?php

namespace Encryption;

use \Encryption\Exceptions\FailDecryptException;

class Encryption
{

    private string $key;
    private string $securityKey;
    private string $cipher;
    private string $cipherHMAC;

    function __construct(string $key, string $securityKey, string $cipher = 'aes-256-cbc', string $cipherHMAC = 'sha384')
    {
        $this->key = $key;
        $this->securityKey = $securityKey;
        $this->cipher = $cipher;
        $this->cipherHMAC = $cipherHMAC;
    }

    private function getKey(): string
    {
        return $this->key;
    }

    private function getSecurityKey(): string
    {
        return $this->securityKey;
    }

    function getCipher(): string
    {
        return $this->cipher;
    }

    function getCipherHMAC(): string
    {
        return $this->cipherHMAC;
    }

    public function setCipher(string $cipher)
    {
        $this->cipher = $cipher;
        return $this;
    }

    public function setCipherHMAC(string $cipherHMAC)
    {
        $this->cipherHMAC = $cipherHMAC;
        return $this;
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
        $textHMAC = static::makeSignature($Encryption, $IV . $textEncrypt);
        return base64_encode($textHMAC . $IV . $textEncrypt);
    }

    static public function makeSignature(self $Encryption, string $content): string
    {
        return hash_hmac($Encryption->getCipherHMAC(), $content, $Encryption->getSecurityKey(), true);
    }

    static public function compareSignature(self $Encryption, string $content, string $HMAC): bool
    {
        return hash_equals(hash_hmac($Encryption->getCipherHMAC(), $content, $Encryption->getSecurityKey(), true), $HMAC);
    }

    static function decrypt(self $Encryption, string $token): string
    {
        static::validateCipher($Encryption->getCipher());
        static::validateCipherHMAC($Encryption->getCipherHMAC());

        $token = base64_decode($token);

        $textHMAC = mb_substr($token, 0, 48, '8bit');
        $IV = mb_substr($token, 48, openssl_cipher_iv_length($Encryption->getCipher()), '8bit');
        $textEncrypt = mb_substr($token, 48 + openssl_cipher_iv_length($Encryption->getCipher()), null, '8bit');

        if (static::compareSignature($Encryption, $IV . $textEncrypt, $textHMAC) == false) {
            throw new FailDecryptException('Token is not equal that was generated.');
        }

        $text = openssl_decrypt($textEncrypt, $Encryption->getCipher(), $Encryption->getKey(), OPENSSL_RAW_DATA, $IV);

        if (empty($text))
            throw new FailDecryptException('Token cannot be decrypted. Check encrypt key.');

        return $text;
    }

}
