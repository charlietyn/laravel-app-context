<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Multi-Tenancy Enabled
    |--------------------------------------------------------------------------
    |
    | Master switch to enable/disable the entire tenancy system.
    |
    | When FALSE:
    | - TenantScope will NOT be applied to models
    | - TenantContextManager will be a no-op
    | - Middleware validation will be skipped
    | - No tenant_id auto-setting on model creation
    |
    | When NULL:
    | - Auto-detect based on app-context channel configuration
    |   (looks for channels with tenant_mode = 'multi')
    |
    | Performance Impact:
    | - Disabled: 0% overhead (code paths bypassed entirely)
    | - Enabled: ~2-5% overhead (scope filtering per query)
    |
    */
    'enabled' => env('TENANCY_ENABLED', null),

    /*
    |--------------------------------------------------------------------------
    | Tenant Column Name
    |--------------------------------------------------------------------------
    |
    | Default column name used across all tenant-aware models.
    | Individual models can override this via the $tenantColumn property.
    |
    */
    'tenant_column' => env('TENANCY_COLUMN', 'tenant_id'),

    /*
    |--------------------------------------------------------------------------
    | Enforcement Mode
    |--------------------------------------------------------------------------
    |
    | Determines behavior when tenant context is missing on a request:
    |
    | - 'strict':   Throw exception if tenant context is absent (production)
    | - 'soft':     Log warning but allow the query (development/testing)
    | - 'disabled': No enforcement at all (single-tenant mode)
    |
    */
    'enforcement_mode' => env('TENANCY_ENFORCEMENT_MODE', 'strict'),

    /*
    |--------------------------------------------------------------------------
    | Channel-Specific Overrides
    |--------------------------------------------------------------------------
    |
    | Override tenancy per channel (app_id). Channels not listed here
    | inherit from the corresponding tenant_mode in config/app-context.php.
    |
    | Set to TRUE to force-enable tenancy for a channel, FALSE to disable,
    | or NULL to inherit from app-context.channels.{channel}.tenant_mode.
    |
    */
    'channels' => [
        'admin'   => env('TENANCY_ADMIN_ENABLED', null),
        'mobile'  => env('TENANCY_MOBILE_ENABLED', null),
        'site'    => env('TENANCY_SITE_ENABLED', null),
        'partner' => env('TENANCY_PARTNER_ENABLED', null),
    ],

    /*
    |--------------------------------------------------------------------------
    | Model Exceptions (Always Excluded)
    |--------------------------------------------------------------------------
    |
    | Models that should NEVER have tenancy applied, regardless of global
    | settings. Typically lookup tables, system tables, and shared resources.
    |
    */
    'exempt_models' => [
        \Modules\location\Models\Countries::class,
        \Modules\location\Models\States::class,
        \Modules\core\Models\Tenants::class,
        \App\Models\Error_logs::class,
    ],

    /*
    |--------------------------------------------------------------------------
    | Auto-Detection Settings
    |--------------------------------------------------------------------------
    |
    | When 'enabled' is NULL, the system auto-detects tenancy by scanning
    | the app-context channel configuration for tenant_mode = 'multi'.
    |
    */
    'auto_detect' => [
        'enabled'   => true,
        'cache_ttl' => 3600,
    ],

    /*
    |--------------------------------------------------------------------------
    | Performance Optimizations
    |--------------------------------------------------------------------------
    */
    'performance' => [
        // Cache tenant context to avoid repeated lookups within the same request
        'cache_context' => true,

        // Skip scope on relations already filtered by parent tenant
        'optimize_relations' => true,

        // Batch tenant validation for bulk operations
        'batch_validation' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Audit & Logging
    |--------------------------------------------------------------------------
    */
    'audit' => [
        // Log when tenancy scope is explicitly bypassed
        'log_bypasses' => env('TENANCY_LOG_BYPASSES', true),

        // Log tenant context changes within a single request
        'log_context_changes' => env('TENANCY_LOG_CONTEXT_CHANGES', false),

        // Alert on cross-tenant access attempts
        'alert_violations' => env('TENANCY_ALERT_VIOLATIONS', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Authorization
    |--------------------------------------------------------------------------
    |
    | Optional callback used to determine whether the authenticated user can
    | execute cross-tenant queries (forTenant/withoutTenant).
    |
    | Signature: fn (mixed $user): bool
    |
    */
    'authorization' => [
        'superuser_resolver' => null,
    ],

];
