<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Middleware;

use Charlietyn\AppContext\Context\AppContext;
use Charlietyn\AppContext\Exceptions\AuthorizationException;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware: Require All Scopes
 *
 * Verifies that user/client has ALL required scopes/capabilities.
 *
 * Usage:
 * Route::middleware(['require.all.scopes:admin:read,admin:write']) // AND logic
 */
class RequireAllScopes
{
    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param Closure $next
     * @param string ...$scopes Required scopes (ALL must be present)
     * @return Response
     */
    public function handle(Request $request, Closure $next, string ...$scopes): Response
    {
        /** @var AppContext $context */
        $context = $request->attributes->get('app_context');

        if (! $context) {
            throw AuthorizationException::insufficientPermissions();
        }

        // If no scopes specified, continue
        if (empty($scopes)) {
            return $next($request);
        }

        // Verify ALL scopes (AND logic)
        $missingScopes = [];
        foreach ($scopes as $scope) {
            if (! $context->hasScope($scope) && ! $context->hasCapability($scope)) {
                $missingScopes[] = $scope;
            }
        }

        if (! empty($missingScopes)) {
            $authType = $context->getAuthMode() === 'api_key' ? 'capabilities' : 'scopes';

            throw new AuthorizationException(
                "Missing required {$authType}: " . implode(', ', $missingScopes),
                $missingScopes
            );
        }

        return $next($request);
    }
}
