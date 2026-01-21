<?php

declare(strict_types=1);

namespace Ronu\AppContext\Middleware;

use Ronu\AppContext\Context\AppContext;
use Ronu\AppContext\Exceptions\AuthorizationException;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware that requires specific scopes or capabilities.
 *
 * Usage:
 *   Route::middleware(['app.scope:admin:users:read'])
 *   Route::middleware(['app.scope:admin:users:read,admin:users:write']) // OR
 *   Route::middleware(['app.scope:admin:*']) // Wildcard
 */
class RequireScope
{
    /**
     * Handle an incoming request.
     *
     * @param string $scopes Comma-separated scopes (any match = pass)
     */
    public function handle(Request $request, Closure $next, string $scopes): Response
    {
        /** @var AppContext|null $context */
        $context = $request->attributes->get('app_context');

        if ($context === null) {
            throw AuthorizationException::insufficientPermissions();
        }

        // Parse scopes
        $requiredScopes = array_map('trim', explode(',', $scopes));

        // Check if any scope matches
        $hasPermission = false;

        foreach ($requiredScopes as $scope) {
            if ($context->hasScope($scope) || $context->hasCapability($scope)) {
                $hasPermission = true;
                break;
            }
        }

        if (! $hasPermission) {
            throw AuthorizationException::missingAnyPermission($requiredScopes);
        }

        return $next($request);
    }
}
