<?php

declare(strict_types=1);

namespace Ronu\AppContext\Middleware;

use Ronu\AppContext\Context\AppContext;
use Ronu\AppContext\Exceptions\AuthorizationException;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware: Require All Abilities
 *
 * Verifies that user/client has ALL required scopes/capabilities.
 *
 * Usage:
 * Route::middleware(['app.requires.all:admin:read,admin:write']) // AND logic
 */
class RequireAllAbilities
{
    /**
     * Handle an incoming request.
     *
     * @param string ...$abilities Required abilities (ALL must be present)
     */
    public function handle(Request $request, Closure $next, string ...$abilities): Response
    {
        /** @var AppContext $context */
        $context = $request->attributes->get('app_context');

        if (! $context) {
            throw AuthorizationException::insufficientPermissions();
        }

        if (empty($abilities)) {
            return $next($request);
        }

        $missing = [];
        foreach ($abilities as $ability) {
            if (! $context->hasAbility($ability)) {
                $missing[] = $ability;
            }
        }

        if (! empty($missing)) {
            $authType = $context->getAuthMode() === 'api_key' ? 'capabilities' : 'scopes';

            throw new AuthorizationException(
                "Missing required {$authType}: " . implode(', ', $missing),
                $missing
            );
        }

        return $next($request);
    }
}
