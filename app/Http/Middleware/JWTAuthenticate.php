<?php

namespace App\Http\Middleware;

use Closure;
use Tymon\JWTAuth\JWTAuth;

class JWTAuthenticate
{
    /**
     * The authentication guard factory instance.
     *
     * @var \Tymon\JWTAuth\JWTAuth
     */
    protected $auth;

    /**
     * Create a new middleware instance.
     *
     * @param  \Tymon\JWTAuth\JWTAuth  $auth
     * @return void
     */
    public function __construct(JWTAuth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = "api")
    {
        try {
            if ($user = $this->auth->parseToken()->authenticate()) {
                return $next($request);
            }
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response("Token expired!", 190);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response("Token invalid", 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response($e->getMessage(), 401);
        }
        return response("Unauthorized.", 401);
    }
}
