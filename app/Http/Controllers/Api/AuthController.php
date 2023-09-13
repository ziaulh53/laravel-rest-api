<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\LogoutRequest;
use App\Http\Requests\SignupRequest;
use App\Models\User;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function  signup(SignupRequest $request)
    {
        $data = $request->validated();

        /** @var \App\Models\User $user */
        $user = User::create([
            'name' => $request['name'],
            'email' => $request['email'],
            'password' => bcrypt($request['password']),
        ]);

        $token =  $user->createToken('main')->plainTextToken;
        return response(compact('user', 'token'));
    }
    public function  login(LoginRequest $request)
    {

        $credential = $request->validated();
        if (!Auth::attempt($credential)) {
            return response([
                'message' => 'Email or Password is incorrect',
                'success' => false
            ], 422);
        }
        /** @var User $user */
        $user  = Auth::user();
        $token = $user->createToken('main')->plainTextToken;
        $success = true;
        return response(compact('user', 'token', 'success'));
    }
    public function logout(LogoutRequest $request)
    {
        /** @var User $user */
        $user = $request->user();
        $user->currentAccessToken()->delete;
        return response(['success'=>true]);
    }
}
