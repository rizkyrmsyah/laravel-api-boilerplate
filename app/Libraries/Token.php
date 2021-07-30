<?php
namespace App\Libraries;

use \Firebase\JWT\JWT;

class Token
{
    public static function generate($length)
    {
        $codeAlphabet = "0123456789";
        $token = "";
        $max = strlen($codeAlphabet);
        for ($i = 0; $i < $length; $i++) {
            $token .= $codeAlphabet[random_int(0, $max - 1)];
        }
        return $token;
    }

    public static function jwtEncode($id)
    {
        $key = base64_encode(env('JWT_SECRETKEY'));
        $tokenId = base64_encode(uniqid(32));
        $issuedAt = time();
        $notBefore = $issuedAt + env('JWT_NBF');
        $expire = $notBefore + env('JWT_EXP');

        $token = array(
            "jti" => $tokenId,
            "iss" => env('JWT_ISS'),
            "iat" => $issuedAt,
            "nbf" => $notBefore,
            'exp' => $expire,
            'data' => [
                'id' => $id,
                'env' => env('APP_ENV'),
            ],
        );
        JWT::$leeway = 5;
        $jwt = JWT::encode($token, $key, env('JWT_ALG'));

        return array($jwt, $expire);
    }
}
