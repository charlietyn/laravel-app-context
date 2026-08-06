<?php

namespace Ronu\AppContext\Middleware;



use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Ronu\AppContext\Context\AppContext;
use Ronu\AppContext\Services\Tenancy\TenantContextManager;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * TenantOwnershipValidator Middleware
 *
 * Ensures the request has a valid tenant context before it reaches
 * the controller. Integrates with AppContext to hydrate the
 * TenantContextManager with the tenant ID from the JWT / API key.
 *
 * Should be registered AFTER ctx.auth / ctx.bind in the middleware stack.
 */
class TenantOwnershipValidator
{
    public function __construct(
        private TenantContextManager $tenantManager,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        // Short-circuit: tenancy globally disabled
        if (!$this->tenantManager->isTenancyEnabled()) {
            return $next($request);
        }

        // Short-circuit: current channel has tenancy disabled
        if (!$this->tenantManager->isEnabledForChannel()) {
            return $next($request);
        }

        // Skip for public / anonymous routes
        if ($this->isPublicRoute($request)) {
            return $next($request);
        }

        // No enforcement -> skip
        if ($this->tenantManager->getEnforcementMode() === 'disabled') {
            return $next($request);
        }

        // Hydrate tenant context from AppContext (set by ctx.auth middleware)
        $this->hydrateFromAppContext($request);

        // Verify tenant context is set
        if (!$this->tenantManager->hasTenantContext()) {
            Log::error('Tenant validation failed: no tenant context', [
                'path'    => $request->path(),
                'user_id' => auth()->id(),
                'ip'      => $request->ip(),
            ]);

            if ($this->tenantManager->getEnforcementMode() === 'strict') {
                throw new HttpException(403, 'Tenant context not set.');
            }
        }

        return $next($request);
    }

    /**
     * Pull tenant ID from the AppContext that was already resolved
     * by the upstream ctx.auth / ctx.bind middleware.
     */
    private function hydrateFromAppContext(Request $request): void
    {
        /** @var AppContext|null $context */
        $context = $request->attributes->get('app_context');

        if ($context instanceof AppContext && $context->tenantId !== null) {
            $this->tenantManager->setTenantId($context->tenantId);
        }
    }

    /**
     * Check if the current route is considered public/unauthenticated.
     */
    private function isPublicRoute(Request $request): bool
    {
        $route = $request->route();

        if (!$route) {
            return false;
        }

        $publicNames = config('app-context.public_routes.names', []);
        $publicEndings = config('app-context.public_routes.path_endings', []);

        // By route name
        if ($route->getName() && in_array($route->getName(), $publicNames, true)) {
            return true;
        }

        // By path ending
        $path = '/' . ltrim($request->path(), '/');
        foreach ($publicEndings as $ending) {
            if (str_ends_with($path, $ending)) {
                return true;
            }
        }

        return false;
    }
}
