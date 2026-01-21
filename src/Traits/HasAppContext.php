<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Traits;

use Charlietyn\AppContext\Context\AppContext;

/**
 * Trait for controllers that need to access AppContext.
 *
 * Usage:
 * class MyController extends Controller
 * {
 *     use HasAppContext;
 *
 *     public function index()
 *     {
 *         $userId = $this->context()->userId;
 *         if ($this->hasScope('admin:export')) {
 *             // ...
 *         }
 *     }
 * }
 */
trait HasAppContext
{
    /**
     * Get the current application context.
     */
    protected function context(): AppContext
    {
        return app(AppContext::class);
    }

    /**
     * Get the current app ID (channel).
     */
    protected function appId(): string
    {
        return $this->context()->appId;
    }

    /**
     * Get the current user ID (if authenticated via JWT).
     */
    protected function userId(): ?string
    {
        return $this->context()->userId;
    }

    /**
     * Get the current client ID (if authenticated via API Key).
     */
    protected function clientId(): ?string
    {
        return $this->context()->clientId;
    }

    /**
     * Get the current tenant ID.
     */
    protected function tenantId(): ?string
    {
        return $this->context()->tenantId;
    }

    /**
     * Check if the current context has a scope.
     */
    protected function hasScope(string $scope): bool
    {
        return $this->context()->hasScope($scope);
    }

    /**
     * Check if the current context has all scopes.
     */
    protected function hasAllScopes(array $scopes): bool
    {
        return $this->context()->hasAllScopes($scopes);
    }

    /**
     * Check if the current context has any of the scopes.
     */
    protected function hasAnyScope(array $scopes): bool
    {
        return $this->context()->hasAnyScope($scopes);
    }

    /**
     * Check if the current context has a capability.
     */
    protected function hasCapability(string $capability): bool
    {
        return $this->context()->hasCapability($capability);
    }

    /**
     * Check if the current context is authenticated.
     */
    protected function isAuthenticated(): bool
    {
        return $this->context()->isAuthenticated();
    }

    /**
     * Check if the current context is anonymous.
     */
    protected function isAnonymous(): bool
    {
        return $this->context()->isAnonymous();
    }

    /**
     * Check if the current channel is admin.
     */
    protected function isAdmin(): bool
    {
        return $this->context()->appId === 'admin';
    }

    /**
     * Check if the current channel is mobile.
     */
    protected function isMobile(): bool
    {
        return $this->context()->appId === 'mobile';
    }

    /**
     * Check if the current channel is site.
     */
    protected function isSite(): bool
    {
        return $this->context()->appId === 'site';
    }

    /**
     * Check if the current channel is partner.
     */
    protected function isPartner(): bool
    {
        return $this->context()->appId === 'partner';
    }

    /**
     * Abort if scope is missing.
     */
    protected function requireScope(string $scope, string $message = null): void
    {
        if (!$this->hasScope($scope)) {
            abort(403, $message ?? "Missing required scope: {$scope}");
        }
    }

    /**
     * Abort if capability is missing.
     */
    protected function requireCapability(string $capability, string $message = null): void
    {
        if (!$this->hasCapability($capability)) {
            abort(403, $message ?? "Missing required capability: {$capability}");
        }
    }
}
