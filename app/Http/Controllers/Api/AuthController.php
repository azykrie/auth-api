<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
        ]);

        if ($validator->fails()) {
            if ($validator->errors()->has('email')) {
                return response()->json([
                    'message' => 'Email sudah terdaftar, silakan gunakan email lain.'
                ], 400);
            }
    
            return response()->json($validator->errors(), 400);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        $token = $user->createToken('AuthToken');

        return response()->json([
            'message' => 'Register berhasil!',
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
    }

    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');
    
        if (!Auth::attempt($credentials)) {
            return response()->json([
                'message' => 'Invalid login credentials'
            ], 401);
        }
    
        $user = User::where('email', $request->email)->firstOrFail();
    
        if ($user->tokens()->count() > 0) {
            return response()->json([
                'message' => 'Anda sudah login!'
            ], 403);
        }
    
        $token = $user->createToken('auth_token')->plainTextToken;
    
        return response()->json([
            'message' => 'Login berhasil!',
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
    }
    
    

    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();

        return response()->json([
            'message' => 'Successfully logged out'
        ]);
    }
}
