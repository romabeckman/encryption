<?php

namespace Encryption;

use \Encryption\Encryption;
use \Encryption\Payload;
use \Encryption\Exceptions\FailDecryptException;

class Jwt
{

    static private $allowed = [
        'sha256' => 'HS256',
        'sha384' => 'HS384',
        'sha512' => 'HS512'
    ];

    static function encode(Encryption $Encryption, Payload $Payload, $urlEncode = false): string
    {
        $data = Payload::transformToArray($Payload);

        $headers = [
            "alg" => static::getAlg($Encryption->getCipherHMAC()),
            "typ" => "JWT"
        ];

        $content = base64_encode(json_encode($headers));
        $content .= '.' . base64_encode(json_encode($data));

        $signature = Encryption::makeSignature($Encryption, $content);

        $jwt = $content . '.' . base64_encode($signature);

        return $urlEncode ? urlencode($jwt) : $jwt;
    }

    static function decode(Encryption $Encryption, string $token): Payload
    {
        [$header, $data, $signature] = explode('.', $token);

        static::validateHeader(json_decode(base64_decode($header), true));

        $signature = base64_decode($signature);
        if (Encryption::compareSignature($Encryption, $header . '.' . $data, $signature) == false) {
            throw new FailDecryptException('Token is not equal that was generated.');
        }


        $Payload = Payload::transformToPayload(json_decode(base64_decode($data), true));
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
        if (!in_array($header['alg'], static::$allowed))
            throw new UnexpectedValueException('alg ' . $header['alg'] . ' in header is not allowed.');
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
