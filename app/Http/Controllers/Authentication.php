<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\ValidationData;
use App\User;

class Authentication {

    public function signup(Request $request) {
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed'
        ]);
        $user = new User([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);
        $user->save();
        return response()->json([
            'message' => 'Successfully created user!'
        ], 201);
    }

    public function login(Request $request) {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
            'remember_me' => 'boolean'
        ]);
        $credentials = request(['email', 'password']);
        if(!Auth::attempt($credentials))
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        $user = $request->user();
        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;
        if ($request->remember_me)
            $token->expires_at = Carbon::now()->addWeeks(1);
        $token->save();
        return response()->json([
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => Carbon::parse(
                $tokenResult->token->expires_at
            )->toDateTimeString()
        ]);
    }

    public function create() {
        $signer = new Sha256();

        $token = (new Builder())->setIssuer('http://example.com') // Configures the issuer (iss claim)
        ->setAudience('super_admin|moderator|content_manager') // Configures the audience (aud claim)
        ->setId('4f1g23a12aa', true) // Configures the id (jti claim), replicating as a header item
        ->setIssuedAt(time()) // Configures the time that the token was issue (iat claim)
        ->setNotBefore(time()) // Configures the time that the token can be used (nbf claim)
        ->setExpiration(time() + 60) // Configures the expiration time of the token (exp claim)
        ->set('uid', 1) // Configures a new claim, called "uid"
        ->sign($signer, '123456789') // creates a signature using "testing" as key
        ->getToken(); // Retrieves the generated token


        echo $token;

    }

    public function validate() {
        $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImp0aSI6IjRmMWcyM2ExMmFhIn0.eyJpc3MiOiJodHRwOlwvXC9leGFtcGxlLmNvbSIsImF1ZCI6InN1cGVyX2FkbWlufG1vZGVyYXRvcnxjb250ZW50X21hbmFnZXIiLCJqdGkiOiI0ZjFnMjNhMTJhYSIsImlhdCI6MTU0MjA2OTU4MCwibmJmIjoxNTQyMDY5NTgwLCJleHAiOjE1NDIwNjk2NDAsInVpZCI6MX0.LCF6A2n1jugpC7ZVpLRs7s7Si9AnTn1y_rIsUy1APxA';
        $token = (new Parser())->parse((string) $token);

        $data = new ValidationData(); // It will use the current time to validate (iat, nbf and exp)
        $data->setIssuer($token->getClaim('iss'));
        $data->setAudience($token->getClaim('aud'));
        $data->setId($token->getHeader('jti'));


        $signer = new Sha256();

        var_dump($token->validate($data)); // false, because we created a token that cannot be used before of `time() + 60`
        var_dump($token->verify($signer, '123456789'));

//        $token->getHeaders(); // Retrieves the token header
//        var_dump($token->getClaims()); // Retrieves the token claims

        echo $token->getHeader('jti').PHP_EOL; // will print "4f1g23a12aa"
        echo $token->getClaim('iss').PHP_EOL; // will print "http://example.com"
        echo $token->getClaim('uid').PHP_EOL; // will print "1"
        echo $token->getClaim('aud').PHP_EOL; // will print "1"
    }
}
