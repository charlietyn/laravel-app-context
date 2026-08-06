<?php

namespace Ronu\AppContext\Services\Tenancy;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Ronu\AppContext\Context\AppContext;

/**
 * TenantContextManager - Conditional Tenant Context Storage
 *
 * Integrates with the existing AppContext system to provide:
 * - Runtime enable/disable of tenancy
 * - Channel-aware tenancy checks
 * - Bypass mode for superadmin operations
 * - Enforcement mode handling (strict/soft/disabled)
 *
 * When tenancy is disabled, all methods become no-ops with zero overhead.
 */
class TenantContextManager
{
    private ?string $currentTenantId = null;
    private bool $bypassMode = false;
    private ?bool $tenancyEnabled = null;

    /**
     * Check if the tenancy system is globally enabled.
     */
    public function isTenancyEnabled(): bool
    {
        if ($this->tenancyEnabled === null) {
            $this->tenancyEnabled = $this->resolveTenancyEnabled();
        }

        return $this->tenancyEnabled;
    }

    /**
     * Resolve whether tenancy is enabled from config + auto-detection.
     */
    private function resolveTenancyEnabled(): bool
    {
        $configured = config('tenancy.enabled');

        // Explicit config takes precedence
        if ($configured !== null) {
            return (bool) $configured;
        }

        // Auto-detect mode
        if (config('tenancy.auto_detect.enabled', true)) {
            return $this->autoDetectTenancy();
        }

        return false;
    }

    /**
     * Auto-detect tenancy by scanning app-context channel configuration
     * for channels with tenant_mode = 'multi'.
     */
    private function autoDetectTenancy(): bool
    {
        $cacheKey = 'tenancy:auto_detect:enabled';
        $cacheTtl = config('tenancy.auto_detect.cache_ttl', 3600);

        return Cache::remember($cacheKey, $cacheTtl, function () {
            try {
                $channels = config('app-context.channels', []);

                $multiTenantChannels = collect($channels)->filter(function ($channelConfig) {
                    return ($channelConfig['tenant_mode'] ?? 'single') === 'multi';
                });

                if ($multiTenantChannels->isNotEmpty()) {
                    Log::info('Tenancy auto-detected: multi-tenant channels found', [
                        'channels' => $multiTenantChannels->keys()->all(),
                    ]);
                    return true;
                }

                Log::info('Tenancy auto-detect: disabled (no multi-tenant channels configured)');
                return false;
            } catch (\Throwable $e) {
                Log::warning('Tenancy auto-detect failed, defaulting to disabled', [
                    'error' => $e->getMessage(),
                ]);
                return false;
            }
        });
    }

    /**
     * Set the current tenant ID.
     *
     * No-op when tenancy is disabled.
     */
    public function setTenantId(?string $tenantId): void
    {
        if (!$this->isTenancyEnabled()) {
            return;
        }

        if (
            config('tenancy.audit.log_context_changes', false)
            && $this->currentTenantId !== null
            && $this->currentTenantId !== $tenantId
        ) {
            Log::warning('Tenant context changed mid-request', [
                'previous' => $this->currentTenantId,
                'new'      => $tenantId,
            ]);
        }

        $this->currentTenantId = $tenantId;
    }

    /**
     * Get the current tenant ID.
     *
     * Returns null when tenancy is disabled.
     */
    public function getTenantId(): ?string
    {
        if (!$this->isTenancyEnabled()) {
            return null;
        }

        // If not yet set, try to pull from AppContext
        if ($this->currentTenantId === null) {
            $this->syncFromAppContext();
        }

        return $this->currentTenantId;
    }

    /**
     * Synchronise tenant ID from the current AppContext stored on the request.
     */
    private function syncFromAppContext(): void
    {
        try {
            $request = request();
            $context = $request?->attributes?->get('app_context');

            if ($context instanceof AppContext && $context->tenantId !== null) {
                $this->currentTenantId = $context->tenantId;
            }
        } catch (\Throwable) {
            // Request or AppContext not available (CLI, queue, etc.)
        }
    }

    /**
     * Check if a tenant context is currently active.
     */
    public function hasTenantContext(): bool
    {
        return $this->isTenancyEnabled() && $this->getTenantId() !== null;
    }

    /**
     * Enable bypass mode (for superadmin cross-tenant operations).
     */
    public function enableBypass(): void
    {
        if (!$this->isTenancyEnabled()) {
            return;
        }

        $this->bypassMode = true;

        if (config('tenancy.audit.log_bypasses', true)) {
            Log::warning('Tenant bypass mode ENABLED', [
                'user_id' => auth()->id(),
            ]);
        }
    }

    /**
     * Disable bypass mode.
     */
    public function disableBypass(): void
    {
        $this->bypassMode = false;
    }

    /**
     * Check if bypass mode is active.
     */
    public function isBypassEnabled(): bool
    {
        return $this->isTenancyEnabled() && $this->bypassMode;
    }

    /**
     * Check if tenancy is enabled for a specific channel.
     *
     * Resolution order:
     *  1. Explicit override in config('tenancy.channels.{channel}')
     *  2. tenant_mode from config('app-context.channels.{channel}')
     *  3. Defaults to true when channel is unknown
     */
    public function isEnabledForChannel(?string $channel = null): bool
    {
        if (!$this->isTenancyEnabled()) {
            return false;
        }

        if ($channel === null) {
            $channel = $this->resolveCurrentChannel();
        }

        if ($channel === null) {
            return true; // Unknown channel -> default enabled
        }

        // 1. Check explicit override
        $override = config("tenancy.channels.{$channel}");

        if ($override !== null) {
            return (bool) $override;
        }

        // 2. Inherit from app-context tenant_mode
        $tenantMode = config("app-context.channels.{$channel}.tenant_mode", 'single');

        return $tenantMode === 'multi';
    }

    /**
     * Resolve the current channel from the AppContext on the request.
     */
    private function resolveCurrentChannel(): ?string
    {
        try {
            $request = request();
            $context = $request?->attributes?->get('app_context');

            if ($context instanceof AppContext) {
                return $context->appId;
            }
        } catch (\Throwable) {
            // Not available
        }

        return null;
    }

    /**
     * Get the current enforcement mode.
     */
    public function getEnforcementMode(): string
    {
        if (!$this->isTenancyEnabled()) {
            return 'disabled';
        }

        return config('tenancy.enforcement_mode', 'strict');
    }

    /**
     * Reset internal state (useful for testing).
     */
    public function reset(): void
    {
        $this->currentTenantId = null;
        $this->bypassMode = false;
        $this->tenancyEnabled = null;
    }
}
