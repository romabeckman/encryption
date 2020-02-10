<?php

namespace Encryption;

use \Encryption\Encryption;
use \Encryption\Payload;
use \Encryption\Utils;
use \Encryption\Exceptions\FailDecryptException;

class Jwt
{

    static private $allowed = [
        'sha256' => 'HS256',
        'sha384' => 'HS384',
        'sha512' => 'HS512'
    ];

    static function encode(Encryption $Encryption, Payload $Payload): string
    {
        $data = Payload::transformToArray($Payload);

        $header = [
            "alg" => static::getAlg($Encryption->getCipherHMAC()),
            "typ" => "JWT"
        ];

        $jwt = Utils::base64UrlEncode(json_encode($header));
        $jwt .= '.';
        $jwt .= Utils::base64UrlEncode(json_encode($data));
        $jwt .= '.' . Utils::base64UrlEncode(Encryption::makeSignature($Encryption, $jwt));

        return $jwt;
    }

    static function decode(Encryption $Encryption, string $token): Payload
    {
        [$header, $data, $signature] = explode('.', $token);

        $headerDecoded = json_decode(Utils::base64UrlDecode($header), true);

        static::validateHeader($headerDecoded);

        $Encryption->setCipherHMAC(array_flip(static::$allowed)[$headerDecoded['alg']]);

        if (Encryption::compareSignature($Encryption, $header . '.' . $data, Utils::base64UrlDecode($signature)) == false) {
            throw new FailDecryptException('Token is not equal that was generated.');
        }

        $Payload = Payload::transformToPayload(json_decode(Utils::base64UrlDecode($data), true));
        Payload::validatePayload($Payload);

        return $Payload;
    }

    static function validateHeader(array $header)
    {
        if (!isset($header)) {
            throw new InvalidArgumentException('header is required');
        }
        if (!isset($header['alg'])) {
            throw new UnexpectedValueException('alg in header is missing');
        }
        if (!isset($header['typ'])) {
            throw new UnexpectedValueException('typ in header is missing');
        }
        if (!in_array($header['alg'], static::$allowed)) {
            throw new UnexpectedValueException('alg ' . $header['alg'] . ' in header is not allowed.');
        }
        if (strcmp($header['typ'], 'JWT') !== 0) {
            throw new UnexpectedValueException('typ must be JWT in header');
        }
    }

    static public function getAlg($cipher): string
    {
        $cipher = strtolower($cipher);

        if (!isset(static::$allowed[$cipher]))
            throw new InvalidArgumentException("Ciphet {$cipher} not allowed");

        return static::$allowed[$cipher];
    }

}
