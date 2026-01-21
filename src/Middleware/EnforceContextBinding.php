<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Middleware;

use Charlietyn\AppContext\Context\AppContext;
use Charlietyn\AppContext\Exceptions\ContextBindingException;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware that enforces context bindings.
 *
 * Validates:
 * - JWT audience matches channel (token.aud === ctx.appId)
 * - API Key channel matches (client.channel === ctx.appId)
 * - Tenant binding (token.tid === request.tenantId)
 */
class EnforceContextBinding
{
    protected bool $enforceAudience;
    protected bool $enforceTenant;

    public function __construct()
    {
        $this->enforceAudience = config('app-context.jwt.verify_aud', true);
        $this->enforceTenant = config('app-context.security.enforce_tenant_binding', true);
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        /** @var AppContext|null $context */
        $context = $request->attributes->get('app_context');

        if ($context === null) {
            throw new ContextBindingException('AppContext not resolved');
        }

        // Skip for anonymous
        if (! $context->isAuthenticated()) {
            return $next($request);
        }

        // Validate based on auth mode
        match ($context->getAuthMode()) {
            'jwt' => $this->validateJwtBinding($context, $request),
            'api_key' => $this->validateApiKeyBinding($context, $request),
            default => null,
        };

        return $next($request);
    }

    /**
     * Validate JWT context binding.
     */
    protected function validateJwtBinding(AppContext $context, Request $request): void
    {
        // Validate audience binding
        if ($this->enforceAudience) {
            $tokenAudience = $context->getMetadataValue('audience');

            if ($tokenAudience !== null && $tokenAudience !== $context->getAppId()) {
                throw ContextBindingException::audienceMismatch(
                    expected: $context->getAppId(),
                    actual: $tokenAudience
                );
            }
        }

        // Validate tenant binding
        if ($this->enforceTenant) {
            $this->validateTenantBinding($context, $request);
        }
    }

    /**
     * Validate API Key context binding.
     */
    protected function validateApiKeyBinding(AppContext $context, Request $request): void
    {
        // Client channel is validated during authentication
        // Additional tenant binding check
        if ($this->enforceTenant) {
            $this->validateTenantBinding($context, $request);
        }
    }

    /**
     * Validate tenant binding.
     */
    protected function validateTenantBinding(AppContext $context, Request $request): void
    {
        // Get tenant from request (route parameter or header)
        $requestTenantId = $this->extractRequestTenantId($request);

        if ($requestTenantId === null) {
            return; // No tenant restriction on this request
        }

        $contextTenantId = $context->getTenantId();

        // If multi-tenant mode requires tenant
        $channelConfig = config("app-context.channels.{$context->getAppId()}", []);
        $tenantMode = $channelConfig['tenant_mode'] ?? 'single';

        if ($tenantMode === 'multi') {
            if ($contextTenantId === null) {
                throw ContextBindingException::missingTenant();
            }

            if ($contextTenantId !== $requestTenantId) {
                throw ContextBindingException::tenantMismatch(
                    expected: $requestTenantId,
                    actual: $contextTenantId
                );
            }
        }
    }

    /**
     * Extract tenant ID from request.
     */
    protected function extractRequestTenantId(Request $request): ?string
    {
        // Try route parameter
        if ($tenantId = $request->route('tenant_id')) {
            return (string) $tenantId;
        }

        if ($tenantId = $request->route('tenantId')) {
            return (string) $tenantId;
        }

        // Try header
        if ($tenantId = $request->header('X-Tenant-Id')) {
            return $tenantId;
        }

        // Try query parameter
        if ($tenantId = $request->query('tenant_id')) {
            return $tenantId;
        }

        return null;
    }
}
