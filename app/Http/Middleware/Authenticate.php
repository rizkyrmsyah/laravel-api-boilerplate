<?php

namespace App\Http\Middleware;

use Closure;
use Firebase\JWT\JWT;
use Illuminate\Http\Response;

class Authenticate
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $jwt = $request->header('Authorization');
        if (empty($jwt)) {
            return response()->json(['message' => 'Unauthorize'], Response::HTTP_UNAUTHORIZED);
        }

        $token = JWT::decode($jwt, base64_encode(env('JWT_SECRETKEY')), array(env('JWT_ALG')));
        if ($token->data->env !== env('APP_ENV')) {
            return response()->json(['message' => 'Invalid token environment'], Response::HTTP_UNAUTHORIZED);
        }

        $request->merge(['session' => $token->data]);

        return $next($request);
    }
}
