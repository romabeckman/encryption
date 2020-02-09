<?php

namespace Encryption;

use \Encryption\Encryption;
use \Encryption\Exceptions\InvalidDomainApplicationException;
use \Encryption\Exceptions\ExpiredTokenException;
use \Encryption\Exceptions\TimePassedException;

class JSONWebToken
{

    public static $timestamp = null;
    public static $defaultExpiration = '2 hours';
    public static $compareIss = true;
    private array $data; //“nbf” Defines a date for which the token cannot be accepted before it
    private ?string $jti; // “jti” ID of token
    private ?string $iss; // “iss” The domain of the token-generating application
    private ?string $sub; // “sub” It is the subject of the token, but it is widely used to store the user ID
    private ?string $aud; // “aud” Defines who can use the token
    private ?int $exp; // “exp” Token expiration date
    private int $iat; // “iat” Token creation date
    private int $nbf; //“nbf” Defines a date for which the token cannot be accepted before it

    function __construct(array $data, ?int $iat = null, ?int $nbf = null, ?int $exp = null)
    {
        $timestamp = static::$timestamp ?: time();

        $this->data = $data;
        $this->iat = $iat ?: $timestamp;
        $this->nbf = $nbf ?: $timestamp;
        $this->jti = null;
        $this->sub = null;
        $this->aud = null;

        $this->iss = static::$compareIss ? static::getCurrentDomain() : null;

        if (empty($exp))
            $this->exp = empty(static::$defaultExpiration) ? null : strtotime(static::$defaultExpiration);
        else
            $this->exp = $exp;
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

    static public function encode(Encryption $Encryption, self $JSONWebToken, $urlEncode = false): string
    {
        if (static::$compareIss && empty($JSONWebToken->getIss())) {
            throw new InvalidDomainApplicationException('Iss param  is required to continue or set JSONWebToken::$compareIss = false.');
        }

        $json = json_encode(static::getPayload($JSONWebToken));
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
        $payload = Encryption::decrypt($Encryption, $token);
        $payload = (array) json_decode($payload);

        if (function_exists('json_last_error') && $errno = json_last_error()) {
            throw new \DomainException("Error to decode Json: ({$errno}) " . json_last_error_msg());
        }

        if (is_null($payload)) {
            throw new \UnexpectedValueException("Invalid token value");
        }

        static::validatePayload($payload);

        return static::getJWT($payload);
    }

    static private function validatePayload($payload): void
    {
        $timestamp = static::$timestamp ?: time();
        if (isset($payload['nbf']) and!empty($payload['nbf']) && $payload['nbf'] > $timestamp) {
            throw new TimePassedException('Cannot handle token prior to ' . date(\DateTime::ISO8601, $payload['nbf']));
        }

        if (isset($payload['iat']) and!empty($payload['iat']) && $payload['iat'] > $timestamp) {
            throw new TimePassedException('Cannot handle token prior to ' . date(\DateTime::ISO8601, $payload['iat']));
        }

        if (isset($payload['exp']) and!empty($payload['exp']) && $timestamp >= $payload['exp']) {
            throw new ExpiredTokenException('Token is not more valid. Must renew the Token to continue access.');
        }

        if (static::$compareIss) {
            if (!isset($payload['iss'])) {
                throw new InvalidDomainApplicationException('Iss param is required to validate token');
            }

            if (isset($payload['iss']) && strcmp($payload['iss'], static::getCurrentDomain()) !== 0) {
                throw new InvalidDomainApplicationException('The domain application is not valid');
            }
        }
    }

    static private function getPayload(self $JSONWebToken): array
    {
        return [
            "data" => $JSONWebToken->getData(),
            "jti" => $JSONWebToken->getJti(),
            "iss" => $JSONWebToken->getIss(),
            "sub" => $JSONWebToken->getSub(),
            "aud" => $JSONWebToken->getAud(),
            "exp" => $JSONWebToken->getExp(),
            "iat" => $JSONWebToken->getIat(),
            "nbf" => $JSONWebToken->getNbf()
        ];
    }

    static private function getJWT(array $payload): self
    {
        $JSONWebToken = new self((array) $payload['data'], $payload['iat'], $payload['nbf'], $payload['exp']);
        $JSONWebToken
                ->setJti($payload['jti'])
                ->setIss($payload['iss'])
                ->setSub($payload['sub'])
                ->setAud($payload['aud']);

        return $JSONWebToken;
    }

    static private function getCurrentDomain(): string
    {
        return (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . '://' . $_SERVER['HTTP_HOST'];
    }

}
