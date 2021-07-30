<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Libraries\Token;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class SessionController extends Controller
{
    public function register(RegisterRequest $request)
    {
        User::create($request->validated());
        return response()->json(['message' => 'success']);
    }

    public function login(LoginRequest $request)
    {
        $user = User::where('email', '=', $request->input('email'))->first();
        if (!$user || !Hash::check($request->input('password'), $user->password)) {
            return response()->json(['message' => 'Email / No HP dan password kurang tepat']);
        }

        list($jwt, $expire) = Token::jwtEncode($user->id);

        return response()->json([
            'message' => 'Login berhasil',
            'data' => [
                'access_token' => $jwt,
                'expire_at' => $expire,
            ],
        ]);
    }
}
