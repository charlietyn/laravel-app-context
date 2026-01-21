<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Middleware;

use Charlietyn\AppContext\Context\AppContext;
use Charlietyn\AppContext\Contracts\ContextResolverInterface;
use Charlietyn\AppContext\Exceptions\ContextBindingException;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware that resolves AppContext from the request.
 *
 * This is the first middleware in the pipeline and MUST run before any
 * authentication middleware.
 *
 * Detection is based ONLY on:
 * - Host (subdomain extraction)
 * - Request path (prefix matching)
 *
 * SECURITY: Never trusts unsigned headers (X-App, X-Channel)
 */
class ResolveAppContext
{
    public function __construct(
        protected readonly ContextResolverInterface $resolver,
    ) {}

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Resolve context from host/path
        $context = $this->resolver->resolve($request);

        // Check deny by default
        if ($context === null && $this->resolver->isDenyByDefault()) {
            throw ContextBindingException::denyByDefault();
        }

        // If no context and not denying, create a default
        if ($context === null) {
            $context = AppContext::anonymous(
                appId: (string) config('app-context.default_channel', 'default'),
                ipAddress: $request->ip(),
            );
        }

        // Store context in request attributes
        $request->attributes->set('app_context', $context);

        // Also bind to container for DI
        app()->instance(AppContext::class, $context);
        app()->instance('app-context', $context);

        return $next($request);
    }
}
