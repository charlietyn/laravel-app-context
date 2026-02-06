<?php

declare(strict_types=1);

namespace Ronu\AppContext\Middleware;

use Ronu\AppContext\Context\AppContext;
use Ronu\AppContext\Exceptions\AuthenticationException;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware that requires an authenticated context.
 *
 * Useful for channels using optional authentication (e.g. jwt_or_anonymous)
 * where a subset of routes must enforce credentials.
 *
 * Usage:
 *  - app.auth.required              // any authenticated identity (JWT or API key)
 *  - app.auth.required:jwt          // authenticated JWT user is required
 *  - app.auth.required:api_key      // authenticated API key client is required
 */
class RequireAuthenticatedContext
{
    public function handle(Request $request, Closure $next, string $mode = 'any'): Response
    {
        /** @var AppContext|null $context */
        $context = $request->attributes->get('app_context');

        if ($context === null) {
            throw new AuthenticationException('AppContext not resolved. Ensure ResolveAppContext middleware runs first.');
        }

        $normalizedMode = strtolower(trim($mode));

        match ($normalizedMode) {
            'any' => $this->requireAnyAuthentication($context),
            'jwt' => $this->requireJwtAuthentication($context),
            'api_key' => $this->requireApiKeyAuthentication($context),
            default => throw new \InvalidArgumentException("Invalid auth required mode: {$mode}. Supported: any, jwt, api_key."),
        };

        return $next($request);
    }

    protected function requireAnyAuthentication(AppContext $context): void
    {
        if (! $context->isAuthenticated()) {
            throw AuthenticationException::missingToken();
        }
    }

    protected function requireJwtAuthentication(AppContext $context): void
    {
        if ($context->getUserId() === null) {
            throw AuthenticationException::missingToken();
        }
    }

    protected function requireApiKeyAuthentication(AppContext $context): void
    {
        if ($context->getClientId() === null) {
            throw AuthenticationException::missingApiKey();
        }
    }
}
