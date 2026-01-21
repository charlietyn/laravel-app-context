<?php

declare(strict_types=1);

namespace Ronu\AppContext\Traits;

use Ronu\AppContext\Context\AppContext;
use Illuminate\Database\Eloquent\Builder;

/**
 * Trait for Eloquent models that need to be filtered by context.
 *
 * Usage:
 * class Order extends Model
 * {
 *     use ContextualScopes;
 *
 *     // In controller:
 *     Order::forContext()->get();
 *     Order::forTenant()->get();
 * }
 */
trait ContextualScopes
{
    /**
     * Scope query to current context (tenant + user if applicable).
     */
    public function scopeForContext(Builder $query): Builder
    {
        $context = app(AppContext::class);

        // Apply tenant filter
        if ($context->tenantId && $this->hasTenantColumn()) {
            $query->where($this->getTenantColumn(), $context->tenantId);
        }

        // For non-admin channels, also filter by user
        if ($context->appId !== 'admin' && $context->userId && $this->hasUserColumn()) {
            $query->where($this->getUserColumn(), $context->userId);
        }

        return $query;
    }

    /**
     * Scope query to current tenant.
     */
    public function scopeForTenant(Builder $query): Builder
    {
        $context = app(AppContext::class);

        if ($context->tenantId && $this->hasTenantColumn()) {
            $query->where($this->getTenantColumn(), $context->tenantId);
        }

        return $query;
    }

    /**
     * Scope query to current user.
     */
    public function scopeForUser(Builder $query): Builder
    {
        $context = app(AppContext::class);

        if ($context->userId && $this->hasUserColumn()) {
            $query->where($this->getUserColumn(), $context->userId);
        }

        return $query;
    }

    /**
     * Scope query for admin access (no tenant/user filter).
     */
    public function scopeForAdmin(Builder $query): Builder
    {
        $context = app(AppContext::class);

        // Only apply if not admin channel
        if ($context->appId === 'admin') {
            return $query;
        }

        // For non-admin, still apply context filters
        return $this->scopeForContext($query);
    }

    /**
     * Get the tenant column name.
     */
    protected function getTenantColumn(): string
    {
        return property_exists($this, 'tenantColumn')
            ? $this->tenantColumn
            : 'tenant_id';
    }

    /**
     * Get the user column name.
     */
    protected function getUserColumn(): string
    {
        return property_exists($this, 'userColumn')
            ? $this->userColumn
            : 'user_id';
    }

    /**
     * Check if the model has a tenant column.
     */
    protected function hasTenantColumn(): bool
    {
        return in_array($this->getTenantColumn(), $this->getFillable())
            || $this->getConnection()->getSchemaBuilder()->hasColumn($this->getTable(), $this->getTenantColumn());
    }

    /**
     * Check if the model has a user column.
     */
    protected function hasUserColumn(): bool
    {
        return in_array($this->getUserColumn(), $this->getFillable())
            || $this->getConnection()->getSchemaBuilder()->hasColumn($this->getTable(), $this->getUserColumn());
    }

    /**
     * Boot the trait (auto-apply tenant on create).
     */
    public static function bootContextualScopes(): void
    {
        static::creating(function ($model) {
            $context = app(AppContext::class);

            // Auto-fill tenant_id
            if ($context->tenantId && $model->hasTenantColumn() && empty($model->{$model->getTenantColumn()})) {
                $model->{$model->getTenantColumn()} = $context->tenantId;
            }

            // Auto-fill user_id
            if ($context->userId && $model->hasUserColumn() && empty($model->{$model->getUserColumn()})) {
                $model->{$model->getUserColumn()} = $context->userId;
            }
        });
    }
}
