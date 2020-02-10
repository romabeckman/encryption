<?php

namespace Encryption;

use \Encryption\Encryption;
use \Encryption\Exceptions\InvalidDomainApplicationException;
use \Encryption\Exceptions\ExpiredTokenException;
use \Encryption\Exceptions\TimePassedException;

class Payload
{

    public static $timestamp = null;
    public static $compareIss = false;

    private array $data; //“nbf” Defines a date for which the token cannot be accepted before it
    private ?string $jti; // “jti” ID of token
    private ?string $iss; // “iss” The domain of the token-generating application
    private ?string $sub; // “sub” It is the subject of the token, but it is widely used to store the user ID
    private ?string $aud; // “aud” Defines who can use the token
    private ?int $exp; // “exp” Token expiration date
    private int $iat; // “iat” Token creation date
    private int $nbf; //“nbf” Defines a date for which the token cannot be accepted before it

    function __construct(array $data, ?int $exp = null, ?int $iat = null, ?int $nbf = null)
    {
        $timestamp = static::$timestamp ?: time();

        $this->data = $data;
        $this->iat = $iat ?: $timestamp;
        $this->nbf = $nbf ?: $timestamp;
        $this->exp = $exp;
        $this->jti = null;
        $this->sub = null;
        $this->aud = null;
        $this->iss = static::$compareIss ? static::getCurrentDomain() : null;
    }

    public function getData(): array
    {
        return $this->data;
    }

    public function getJti(): ?string
    {
        return $this->jti;
    }

    public function getIss(): ?string
    {
        return $this->iss;
    }

    public function getSub(): ?string
    {
        return $this->sub;
    }

    public function getAud(): ?string
    {
        return $this->aud;
    }

    public function getExp(): ?int
    {
        return $this->exp;
    }

    public function getIat(): int
    {
        return $this->iat;
    }

    public function getNbf(): int
    {
        return $this->nbf;
    }

    public function setJti(?string $jti)
    {
        $this->jti = $jti;
        return $this;
    }

    public function setIss(?string $iss)
    {
        $this->iss = $iss;
        return $this;
    }

    public function setSub(?string $sub)
    {
        $this->sub = $sub;
        return $this;
    }

    public function setAud(?string $aud)
    {
        $this->aud = $aud;
        return $this;
    }

    static public function encode(Encryption $Encryption, self $Payload, $urlEncode = false): string
    {
        if (static::$compareIss && empty($Payload->getIss())) {
            throw new InvalidDomainApplicationException('Iss param  is required to continue or set Payload::$compareIss = false.');
        }

        $json = json_encode(static::transformToArray($Payload));
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            throw new \DomainException("Error to encode Json: ({$errno}) " . json_last_error_msg());
        } elseif (empty($json)) {
            throw new \DomainException("Error to encode Json");
        }

        $token = Encryption::encrypt($Encryption, $json);
        return $urlEncode ? urlencode($token) : $token;
    }

    static public function decode(Encryption $Encryption, string $token): self
    {
        $content = Encryption::decrypt($Encryption, $token);
        $content = json_decode($content, true);

        if (function_exists('json_last_error') && $errno = json_last_error()) {
            throw new \DomainException("Error to decode Json: ({$errno}) " . json_last_error_msg());
        }

        if (is_null($content)) {
            throw new \UnexpectedValueException("Invalid token value");
        }

        $Payload = static::transformToPayload($content);
        static::validatePayload($Payload);
        return $Payload;
    }

    static public function validatePayload(self $Payload): void
    {
        $timestamp = static::$timestamp ?: time();
        if (!empty($Payload->getNbf()) && $Payload->getNbf() > $timestamp) {
            throw new TimePassedException('Cannot handle token prior to ' . date(\DateTime::ISO8601, $Payload->getNbf()));
        }

        if (!empty($Payload->getIat()) && $Payload->getIat() > $timestamp) {
            throw new TimePassedException('Cannot handle token prior to ' . date(\DateTime::ISO8601, $Payload->getIat()));
        }

        if (!empty($Payload->getExp()) && $timestamp >= $Payload->getExp()) {
            throw new ExpiredTokenException('Token is not more valid. Must renew the Token to continue access.');
        }

        if (static::$compareIss) {
            if (empty($Payload->getIss())) {
                throw new InvalidDomainApplicationException('Iss param is required to validate token');
            }

            if (strcmp($Payload->getIss(), static::getCurrentDomain()) !== 0) {
                throw new InvalidDomainApplicationException('The domain application is not valid');
            }
        }
    }

    static public function transformToArray(self $Payload): array
    {
        return [
            "data" => $Payload->getData(),
            "jti" => $Payload->getJti(),
            "iss" => $Payload->getIss(),
            "sub" => $Payload->getSub(),
            "aud" => $Payload->getAud(),
            "exp" => $Payload->getExp(),
            "iat" => $Payload->getIat(),
            "nbf" => $Payload->getNbf()
        ];
    }

    static public function transformToPayload(array $payload): self
    {
        $Payload = new self((array) ($payload['data'] ?? []), $payload['exp'], $payload['iat'], $payload['nbf']);
        $Payload
                ->setJti($payload['jti'] ?? null)
                ->setIss($payload['iss'] ?? null)
                ->setSub($payload['sub'] ?? null)
                ->setAud($payload['aud'] ?? null);

        return $Payload;
    }

    static public function getCurrentDomain(): string
    {
        return (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . '://' . $_SERVER['HTTP_HOST'];
    }

}
