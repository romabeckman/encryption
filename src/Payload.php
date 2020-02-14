<?php

namespace Encryption;

use \Encryption\Encryption;
use \Encryption\Exceptions\InvalidDomainApplicationException;
use \Encryption\Exceptions\ExpiredTokenException;
use \Encryption\Exceptions\TimePassedException;
use \Encryption\Utils;

class Payload
{

    public static $timestamp = null;
    private $data;
    private $jti; // “jti” ID of token
    private $iss; // “iss” The domain of the token-generating application
    private $sub; // “sub” It is the subject of the token, but it is widely used to store the user ID
    private $aud; // “aud” Defines who can use the token
    private $exp; // “exp” Token expiration date
    private $iat; // “iat” Token creation date
    private $nbf; //“nbf” Defines a date for which the token cannot be accepted before it
    private $checkIssDomain; // Force validation of domain and set if iss is empty

    function __construct(array $data, ?int $exp = null, ?int $nbf = null, ?int $iat = null)
    {
        $timestamp = static::$timestamp ?: time();

        $this->data = $data;
        $this->iat = $iat ?: $timestamp;
        $this->nbf = $nbf ?: $this->iat;
        $this->exp = $exp;
        $this->jti = null;
        $this->sub = null;
        $this->aud = null;
        $this->checkIssDomain = false;
        $this->iss = null;
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

    public function getCheckIssDomain(): bool
    {
        return $this->checkIssDomain;
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

    public function setExp(?int $exp)
    {
        $this->exp = $exp;
        return $this;
    }

    public function setCheckIssDomain(bool $checkIssDomain)
    {
        $this->checkIssDomain = $checkIssDomain;
        return $this;
    }

    static public function encode(Encryption $Encryption, self $Payload, bool $urlEncode = false): string
    {
        if ($Payload->getCheckIssDomain() && empty($Payload->getIss())) {
            $Payload->setIss(Utils::getCurrentDomain());
        }

        $json = json_encode(static::transformToArray($Payload));
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            throw new \DomainException("Error to encode Json: ({$errno}) " . json_last_error_msg());
        } elseif (empty($json)) {
            throw new \DomainException("Error to encode Json");
        }

        return Encryption::encrypt($Encryption, $json, $urlEncode);
    }

    static public function decode(Encryption $Encryption, string $token, bool $urlEncode = false): self
    {
        $content = Encryption::decrypt($Encryption, $token, $urlEncode);
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

        if ($Payload->getCheckIssDomain()) {
            if (empty($Payload->getIss())) {
                throw new InvalidDomainApplicationException('Iss param is required to validate token');
            }

            if (strcmp($Payload->getIss(), Utils::getCurrentDomain()) !== 0) {
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
            "nbf" => $Payload->getNbf(),
            "chiss" => $Payload->getCheckIssDomain()
        ];
    }

    static public function transformToPayload(array $payload): self
    {
        if (empty($payload)) {
            throw new InvalidArgumentException('$payload was empty');
        }
        if (!isset($payload['iat'])) {
            throw new UnexpectedValueException('iat is missing in $payload');
        }

        $Payload = new self($payload['data'] ?? [], $payload['exp'] ?? null, $payload['nbf'] ?? null, $payload['iat']);
        $Payload
                ->setJti($payload['jti'] ?? null)
                ->setIss($payload['iss'] ?? null)
                ->setSub($payload['sub'] ?? null)
                ->setAud($payload['aud'] ?? null)
                ->setCheckIssDomain($payload['chiss']);

        return $Payload;
    }

}
