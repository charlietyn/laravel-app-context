<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Middleware;

use Charlietyn\AppContext\Auth\Authenticators\AnonymousAuthenticator;
use Charlietyn\AppContext\Auth\Authenticators\ApiKeyAuthenticator;
use Charlietyn\AppContext\Auth\Authenticators\JwtAuthenticator;
use Charlietyn\AppContext\Context\AppContext;
use Charlietyn\AppContext\Contracts\AuthenticatorInterface;
use Charlietyn\AppContext\Exceptions\AuthenticationException;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware that authenticates the request based on channel auth mode.
 *
 * This middleware runs AFTER ResolveAppContext and handles:
 * - JWT authentication (jwt, jwt_or_anonymous)
 * - API Key authentication (api_key)
 * - Anonymous access (anonymous)
 */
class AuthenticateChannel
{
    public function __construct(
        protected readonly JwtAuthenticator $jwtAuthenticator,
        protected readonly ApiKeyAuthenticator $apiKeyAuthenticator,
        protected readonly AnonymousAuthenticator $anonymousAuthenticator,
    ) {}

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        /** @var AppContext|null $context */
        $context = $request->attributes->get('app_context');

        if ($context === null) {
            throw new AuthenticationException('AppContext not resolved. Ensure ResolveAppContext middleware runs first.');
        }

        // Get the appropriate authenticator
        $authenticator = $this->getAuthenticator($context->getAuthMode());

        try {
            // Authenticate and get enriched context
            $enrichedContext = $authenticator->authenticate($request, $context);

            // Update request attributes
            $request->attributes->set('app_context', $enrichedContext);

            // Update container bindings
            app()->instance(AppContext::class, $enrichedContext);
            app()->instance('app-context', $enrichedContext);

        } catch (AuthenticationException $e) {
            // Log failed authentication
            if (config('app-context.audit.log_failed_auth', true)) {
                Log::warning('Authentication failed', [
                    'channel' => $context->getAppId(),
                    'auth_mode' => $context->getAuthMode(),
                    'error' => $e->getMessage(),
                    'ip' => $request->ip(),
                    'path' => $request->path(),
                ]);
            }

            throw $e;
        }

        return $next($request);
    }

    /**
     * Get the authenticator for the given auth mode.
     */
    protected function getAuthenticator(string $authMode): AuthenticatorInterface
    {
        return match ($authMode) {
            'jwt', 'jwt_or_anonymous' => $this->jwtAuthenticator,
            'api_key' => $this->apiKeyAuthenticator,
            'anonymous' => $this->anonymousAuthenticator,
            default => throw new \InvalidArgumentException("Unknown auth mode: {$authMode}"),
        };
    }
}
