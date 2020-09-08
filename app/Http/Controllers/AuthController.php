<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Psy\Util\Json;

class AuthController extends Controller
{

    /**
     * @param Request $request
     * @return mixed
     * @throws ValidationException
     */
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required'
        ]);

        $user = User::where('email', $request->get('email'))->first();

        if (! $user || ! Hash::check($request->get('password'), $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        return new JsonResponse([
            "user" => $user,
            "token" => $user->createToken('web')->plainTextToken,
        ]);
    }

    public function register(Request $request)
    {
        $request->validate([
            'first_name' => 'required',
            'last_name' => 'required',
            'email' => 'required|email|unique:users,email',
            'address' => 'required',
            'password' => 'required|min:6',
            'confirm_password' => 'required|same:password',
        ]);

        $data = $request
            ->merge(['password' => Hash::make($request->get('password'))])
            ->all(['first_name', 'last_name', 'email', 'address', 'password'])
        ;
        $user = User::create($data);

        return new JsonResponse([
            'data' => $user
        ]);
    }

    public function logout()
    {

    }


}
