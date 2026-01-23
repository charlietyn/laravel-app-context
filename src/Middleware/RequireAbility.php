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
 *   Route::middleware(['app.requires:admin:users:read'])
 *   Route::middleware(['app.requires:admin:users:read,admin:users:write']) // OR
 *   Route::middleware(['app.requires:admin:*']) // Wildcard
 */
class RequireAbility
{
    /**
     * Handle an incoming request.
     *
     * @param string $abilities Comma-separated abilities (any match = pass)
     */
    public function handle(Request $request, Closure $next, string $abilities): Response
    {
        /** @var AppContext|null $context */
        $context = $request->attributes->get('app_context');

        if ($context === null) {
            throw AuthorizationException::insufficientPermissions();
        }

        $required = array_map('trim', explode(',', $abilities));

        if (! $context->hasAnyAbility($required)) {
            throw AuthorizationException::missingAnyPermission($required);
        }

        return $next($request);
    }
}
