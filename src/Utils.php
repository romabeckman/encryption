<?php

namespace Encryption;

class Utils
{
    static function base64UrlEncode(string $data)
    {
        $data = base64_encode($data);

        if (empty($data)) {
            throw new \InvalidArgumentException('$data cant be converted to base64');
        }

        return rtrim(strtr($data, '+/', '-_'), '=');
    }

    static function base64UrlDecode(string $data)
    {
        $data = base64_decode(strtr($data, '-_', '+/'), true);

        if (empty($data)) {
            throw new \InvalidArgumentException('$data cant be converted to base64');
        }

        return $data;
    }

    static function getCurrentDomain(): string
    {
        return (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . '://' . $_SERVER['HTTP_HOST'];
    }
}
