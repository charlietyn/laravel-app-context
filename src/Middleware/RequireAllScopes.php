<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Middleware;

use Charlietyn\AppContext\Context\AppContext;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

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

        if (!$context) {
            throw new HttpException(500, 'App context not resolved');
        }

        // If no scopes specified, continue
        if (empty($scopes)) {
            return $next($request);
        }

        // Verify ALL scopes (AND logic)
        $missingScopes = [];
        foreach ($scopes as $scope) {
            if (!$context->requires($scope)) {
                $missingScopes[] = $scope;
            }
        }

        if (!empty($missingScopes)) {
            $authType = $context->authMode === 'api_key' ? 'capabilities' : 'scopes';
            throw new HttpException(
                403,
                "Missing {$authType}: " . implode(', ', $missingScopes)
            );
        }

        return $next($request);
    }
}
