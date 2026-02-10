<?php

namespace Ronu\AppContext\Scopes;


use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;
use Illuminate\Support\Facades\Log;
use Ronu\AppContext\Services\Tenancy\TenantContextManager;

/**
 * TenantScope - Conditional Automatic Tenant Filtering
 *
 * Applied as a global scope via the TenantAware trait.
 * All checks short-circuit when tenancy is disabled.
 */
class TenantScope implements Scope
{
    /**
     * Apply the scope to a given Eloquent query builder.
     */
    public function apply(Builder $builder, Model $model): void
    {
        /** @var TenantContextManager $manager */
        $manager = app(TenantContextManager::class);

        // Short-circuit: tenancy globally disabled
        if (!$manager->isTenancyEnabled()) {
            return;
        }

        // Short-circuit: current channel has tenancy disabled
        if (!$manager->isEnabledForChannel()) {
            return;
        }

        // Short-circuit: model is exempt
        if ($this->isExemptModel($model)) {
            return;
        }

        // Short-circuit: bypass mode (superadmin)
        if ($manager->isBypassEnabled()) {
            return;
        }

        $tenantId = $manager->getTenantId();
        $mode = $manager->getEnforcementMode();

        if ($tenantId === null) {
            $this->handleMissingContext($builder, $model, $mode);
            return;
        }

        $builder->where($model->getTable() . '.' . $this->getTenantColumn($model), '=', $tenantId);
    }

    /**
     * Extend the query builder with tenant-specific macros.
     */
    public function extend(Builder $builder): void
    {
        /** @var TenantContextManager $manager */
        $manager = app(TenantContextManager::class);

        if (!$manager->isTenancyEnabled()) {
            return;
        }

        // Model::withoutTenantScope()
        $builder->macro('withoutTenantScope', function (Builder $builder) {
            if (config('tenancy.audit.log_bypasses', true)) {
                Log::warning('TenantScope bypassed explicitly', [
                    'model'   => get_class($builder->getModel()),
                    'user_id' => auth()->id(),
                ]);
            }

            return $builder->withoutGlobalScope(TenantScope::class);
        });

        // Model::forTenant($tenantId)
        $builder->macro('forTenant', function (Builder $builder, ?string $tenantId) {
            if (!auth()->user()?->is_superuser) {
                throw new \RuntimeException('forTenant() requires superuser privileges');
            }

            Log::info('Cross-tenant query executed', [
                'target_tenant' => $tenantId,
                'user_id'       => auth()->id(),
            ]);

            $model = $builder->getModel();
            $column = method_exists($model, 'getTenantColumn')
                ? $model->getTenantColumn()
                : config('tenancy.tenant_column', 'tenant_id');

            return $builder
                ->withoutGlobalScope(TenantScope::class)
                ->where($model->getTable() . '.' . $column, '=', $tenantId);
        });
    }

    /**
     * Check if the model is exempt from tenancy.
     */
    private function isExemptModel(Model $model): bool
    {
        $exemptModels = config('tenancy.exempt_models', []);

        return in_array(get_class($model), $exemptModels, true);
    }

    /**
     * Get tenant column from the model or default config.
     */
    private function getTenantColumn(Model $model): string
    {
        if (method_exists($model, 'getTenantColumn')) {
            return $model->getTenantColumn();
        }

        return config('tenancy.tenant_column', 'tenant_id');
    }

    /**
     * Handle query when tenant context is missing.
     */
    private function handleMissingContext(Builder $builder, Model $model, string $mode): void
    {
        switch ($mode) {
            case 'strict':
                // Force empty result set
                $builder->whereRaw('1 = 0');

                Log::error('TenantScope: query blocked -- no tenant context (strict mode)', [
                    'model' => get_class($model),
                ]);

                throw new \RuntimeException(
                    'Tenant context not set. Set TENANCY_ENFORCEMENT_MODE=soft to allow queries without tenant context.'
                );

            case 'soft':
                Log::warning('TenantScope: query allowed without tenant context (soft mode)', [
                    'model' => get_class($model),
                ]);
                break;

            case 'disabled':
            default:
                // Allow all queries
                break;
        }
    }
}
