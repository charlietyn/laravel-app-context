<?php

namespace Ronu\AppContext\Traits;



use Illuminate\Support\Facades\Log;
use Ronu\AppContext\Scopes\TenantScope;
use Ronu\AppContext\Services\Tenancy\TenantContextManager;

/**
 * TenantAware Trait
 *
 * Add to any Eloquent model that should be filtered by tenant.
 * When tenancy is disabled globally, per-channel, or for this specific
 * model class, all behaviour is skipped with zero overhead.
 *
 * Usage:
 *   class Order extends BaseModel { use TenantAware; }
 *
 * Override the default column:
 *   protected string $tenantColumn = 'company_id';
 */
trait TenantAware
{
    /**
     * Boot the TenantAware trait.
     */
    protected static function bootTenantAware(): void
    {
        /** @var TenantContextManager $manager */
        $manager = app(TenantContextManager::class);

        // Early return: skip everything when tenancy is disabled
        if (!$manager->isTenancyEnabled()) {
            return;
        }

        // Skip if this model is explicitly exempt
        if (in_array(static::class, config('tenancy.exempt_models', []), true)) {
            return;
        }

        // Register the global scope
        static::addGlobalScope(new TenantScope());

        // Auto-set tenant_id on creating
        static::creating(function ($model) use ($manager) {
            if (!$manager->isTenancyEnabled()) {
                return;
            }

            // Skip if channel has tenancy disabled
            if (!$manager->isEnabledForChannel()) {
                return;
            }

            $column = $model->getTenantColumn();

            if (!$model->isDirty($column)) {
                $tenantId = $model->getCurrentTenantId();

                if ($tenantId !== null) {
                    $model->setAttribute($column, $tenantId);
                } elseif ($manager->getEnforcementMode() === 'strict') {
                    throw new \RuntimeException(
                        'Cannot create ' . get_class($model) . ' without tenant context (strict mode).'
                    );
                }
            } else {
                // Caller set tenant_id explicitly -- validate it
                $model->validateTenantId();
            }
        });

        // Prevent tenant_id modification on updates
        static::updating(function ($model) use ($manager) {
            if (!$manager->isTenancyEnabled()) {
                return;
            }

            $column = $model->getTenantColumn();

            if ($model->isDirty($column)) {
                Log::error('Attempted tenant_id modification blocked', [
                    'model'           => get_class($model),
                    'id'              => $model->getKey(),
                    'original_tenant' => $model->getOriginal($column),
                    'new_tenant'      => $model->getAttribute($column),
                    'user_id'         => auth()->id(),
                ]);

                throw new \RuntimeException('Cannot modify tenant_id on existing records.');
            }
        });
    }

    /**
     * Get the tenant column name for this model.
     */
    public function getTenantColumn(): string
    {
        return $this->tenantColumn ?? config('tenancy.tenant_column', 'tenant_id');
    }

    /**
     * Get the fully-qualified tenant column (table.column).
     */
    public function getQualifiedTenantColumn(): string
    {
        return $this->qualifyColumn($this->getTenantColumn());
    }

    /**
     * Get the current tenant ID from the TenantContextManager.
     */
    protected function getCurrentTenantId(): ?string
    {
        /** @var TenantContextManager $manager */
        $manager = app(TenantContextManager::class);

        if (!$manager->isTenancyEnabled()) {
            return null;
        }

        return $manager->getTenantId();
    }

    /**
     * Validate that the model's tenant_id matches the current context.
     */
    protected function validateTenantId(): void
    {
        /** @var TenantContextManager $manager */
        $manager = app(TenantContextManager::class);

        if (!$manager->isTenancyEnabled()) {
            return;
        }

        // Bypass mode skips validation
        if ($manager->isBypassEnabled()) {
            return;
        }

        $modelTenantId  = $this->getAttribute($this->getTenantColumn());
        $contextTenantId = $this->getCurrentTenantId();

        // Allow null context in non-strict modes
        if ($contextTenantId === null && $manager->getEnforcementMode() !== 'strict') {
            return;
        }

        if ((string) $modelTenantId !== (string) $contextTenantId) {
            Log::error('Tenant ID mismatch on model operation', [
                'model'          => get_class($this),
                'model_tenant'   => $modelTenantId,
                'context_tenant' => $contextTenantId,
                'user_id'        => auth()->id(),
            ]);

            throw new \RuntimeException(
                "Cannot create/update model with tenant_id '{$modelTenantId}'. "
                . "Current context tenant is '{$contextTenantId}'."
            );
        }
    }

    /**
     * Scope: query across all tenants (superadmin only).
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeWithoutTenant($query)
    {
        if (!auth()->user()?->is_superuser) {
            throw new \RuntimeException('withoutTenant() requires superuser privileges.');
        }

        return $query->withoutGlobalScope(TenantScope::class);
    }

    /**
     * Check if tenancy is currently enabled for this model's context.
     */
    public function isTenancyActive(): bool
    {
        /** @var TenantContextManager $manager */
        $manager = app(TenantContextManager::class);

        return $manager->isTenancyEnabled();
    }
}
