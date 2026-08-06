<?php

namespace Ronu\AppContext\Commands;

use App\Services\Tenancy\TenantContextManager;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Schema;

class TenancyStatus extends Command
{
    protected $signature = 'tenancy:status
                            {--detailed : Show detailed model analysis}';

    protected $description = 'Display current tenancy configuration and status';

    public function handle(): int
    {
        $this->info('Tenancy System Status Check');
        $this->newLine();

        $manager = app(TenantContextManager::class);

        $this->displayGlobalStatus($manager);
        $this->displayChannelConfiguration();

        if ($this->option('detailed')) {
            $this->displayModelAnalysis();
        }

        $this->displayPerformanceSettings();
        $this->displayRecommendations($manager);

        return 0;
    }

    private function displayGlobalStatus(TenantContextManager $manager): void
    {
        $this->info('Global Configuration');

        $configuredValue = config('tenancy.enabled');
        $detectionMethod = $configuredValue === null ? 'Auto-detect' : 'Manual';

        $this->table(
            ['Setting', 'Value'],
            [
                ['Tenancy Enabled', $manager->isTenancyEnabled() ? 'Yes' : 'No'],
                ['Detection Method', $detectionMethod],
                ['Enforcement Mode', config('tenancy.enforcement_mode', 'N/A')],
                ['Tenant Column', config('tenancy.tenant_column', 'tenant_id')],
                ['Log Bypasses', config('tenancy.audit.log_bypasses') ? 'Enabled' : 'Disabled'],
                ['Alert Violations', config('tenancy.audit.alert_violations') ? 'Enabled' : 'Disabled'],
            ]
        );

        $this->newLine();
    }

    private function displayChannelConfiguration(): void
    {
        $this->info('Channel Configuration');

        $appContextChannels = config('app-context.channels', []);
        $tenancyOverrides = config('tenancy.channels', []);
        $rows = [];

        foreach ($appContextChannels as $channel => $channelConfig) {
            $tenantMode = $channelConfig['tenant_mode'] ?? 'unknown';
            $override = $tenancyOverrides[$channel] ?? null;

            if ($override !== null) {
                $effective = $override ? 'Enabled (override)' : 'Disabled (override)';
            } else {
                $effective = $tenantMode === 'multi' ? 'Enabled' : 'Disabled';
            }

            $rows[] = [
                $channel,
                $tenantMode,
                $effective,
            ];
        }

        $this->table(['Channel', 'tenant_mode', 'Effective Tenancy'], $rows);
        $this->newLine();
    }

    private function displayModelAnalysis(): void
    {
        $this->info('Model Analysis (scanning codebase...)');

        $tenantColumn = config('tenancy.tenant_column', 'tenant_id');
        $exemptModels = config('tenancy.exempt_models', []);
        $models = $this->scanModels();
        $rows = [];

        foreach ($models as $model) {
            $hasColumn = $this->modelHasTenantColumn($model, $tenantColumn);
            $isExempt = in_array($model, $exemptModels, true);

            $rows[] = [
                class_basename($model),
                $hasColumn ? 'Yes' : 'No',
                $isExempt ? 'Exempt' : ($hasColumn ? 'Active' : 'N/A'),
            ];
        }

        $this->table(['Model', 'Has ' . $tenantColumn, 'Tenancy Status'], $rows);
        $this->newLine();
    }

    private function displayPerformanceSettings(): void
    {
        $this->info('Performance Settings');

        $this->table(
            ['Optimisation', 'Status'],
            [
                ['Cache Context', config('tenancy.performance.cache_context') ? 'Enabled' : 'Disabled'],
                ['Optimise Relations', config('tenancy.performance.optimize_relations') ? 'Enabled' : 'Disabled'],
                ['Batch Validation', config('tenancy.performance.batch_validation') ? 'Enabled' : 'Disabled'],
            ]
        );

        $this->newLine();
    }

    private function displayRecommendations(TenantContextManager $manager): void
    {
        $this->info('Recommendations');

        $warnings = [];

        if ($manager->isTenancyEnabled()) {
            $appContextChannels = config('app-context.channels', []);
            $enabledCount = collect($appContextChannels)->filter(function ($cfg) {
                return ($cfg['tenant_mode'] ?? 'single') === 'multi';
            })->count();

            if ($enabledCount === 0) {
                $warnings[] = 'Tenancy is enabled but no channels have tenant_mode=multi';
            }
        }

        if (config('tenancy.enabled') === null && !config('tenancy.auto_detect.enabled', true)) {
            $warnings[] = 'TENANCY_ENABLED is null but auto-detect is disabled -- ambiguous configuration';
        }

        if (config('tenancy.enforcement_mode') === 'soft') {
            $warnings[] = 'Soft enforcement mode is active -- consider strict for production';
        }

        if (!empty($warnings)) {
            $this->warn('Warnings:');
            foreach ($warnings as $w) {
                $this->line('  - ' . $w);
            }
        } else {
            $this->info('No issues detected -- configuration looks good.');
        }

        $this->newLine();
    }

    /**
     * Scan known model directories for Eloquent models.
     */
    private function scanModels(): array
    {
        $models = [];

        // app/Models
        foreach (glob(app_path('Models/*.php')) ?: [] as $file) {
            $className = 'App\\Models\\' . basename($file, '.php');
            if (class_exists($className)) {
                $models[] = $className;
            }
        }

        // Modules/*/Models
        foreach (glob(base_path('Modules/*/Models/*.php')) ?: [] as $file) {
            if (preg_match('#Modules/([^/]+)/Models/([^/]+)\.php#', $file, $m)) {
                $className = "Modules\\{$m[1]}\\Models\\{$m[2]}";
                if (class_exists($className)) {
                    $models[] = $className;
                }
            }
        }

        return $models;
    }

    /**
     * Check if a model's table has the tenant column.
     */
    private function modelHasTenantColumn(string $modelClass, string $column): bool
    {
        try {
            $instance = new $modelClass();
            return Schema::connection($instance->getConnectionName())
                ->hasColumn($instance->getTable(), $column);
        } catch (\Throwable) {
            return false;
        }
    }
}
