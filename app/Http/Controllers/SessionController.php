<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Libraries\Token;
use App\Models\RefreshToken;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

class SessionController extends Controller
{
    public function register(RegisterRequest $request)
    {
        User::create($request->validated());
        return response()->json(['message' => 'success'], Response::HTTP_CREATED);
    }

    public function login(LoginRequest $request)
    {
        $user = User::where('email', '=', $request->input('email'))->first();
        if (!$user || !Hash::check($request->input('password'), $user->password)) {
            return response()->json(['message' => 'Email password kurang tepat'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        DB::beginTransaction();
        try {
            list($jwt, $expire) = Token::jwtEncode($user->id);

            $code = '';
            $isTokenExist = false;
            do {
                $code = Token::generate(32);
                $count = RefreshToken::where('token', $code)->count();
                if ($count > 0) {
                    $isTokenExist = true;
                }

            } while ($isTokenExist);

            RefreshToken::create(['token' => $code, 'user_id' => $user->id, 'still_active' => true]);

            $user->last_sign_in_at = Carbon::now();
            $user->save();

            DB::commit();
            return response()->json([
                'message' => 'Login berhasil',
                'data' => [
                    'access_token' => $jwt,
                    'expire_at' => $expire,
                    'refresh_token' => $code,
                ],
            ]);
        } catch (\Exception$exception) {
            DB::rollBack();
            return response()->json(['message' => $exception->getMessage()]);
        }
    }
}
