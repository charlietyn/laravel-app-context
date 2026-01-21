<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Commands;

use Charlietyn\AppContext\Models\ApiClient;
use Illuminate\Console\Command;

class ListApiClientsCommand extends Command
{
    protected $signature = 'app-context:list-clients
                            {--channel= : Filter by channel}
                            {--tenant= : Filter by tenant}
                            {--include-revoked : Include revoked clients}';

    protected $description = 'List all API clients';

    public function handle(): int
    {
        $query = ApiClient::query();

        if ($channel = $this->option('channel')) {
            $query->forChannel($channel);
        }

        if ($tenant = $this->option('tenant')) {
            $query->forTenant($tenant);
        }

        if (! $this->option('include-revoked')) {
            $query->where('is_revoked', false);
        }

        $clients = $query->get();

        if ($clients->isEmpty()) {
            $this->info('No API clients found.');

            return self::SUCCESS;
        }

        $rows = $clients->map(fn (ApiClient $client) => [
            $client->app_code,
            $client->name,
            $client->channel,
            $client->tenant_id ?: '-',
            $client->is_active ? '✓' : '✗',
            $client->is_revoked ? '✓' : '✗',
            $client->expires_at?->format('Y-m-d') ?: 'Never',
            $client->last_used_at?->format('Y-m-d H:i') ?: 'Never',
            number_format($client->usage_count),
        ]);

        $this->table(
            ['Client ID', 'Name', 'Channel', 'Tenant', 'Active', 'Revoked', 'Expires', 'Last Used', 'Usage'],
            $rows
        );

        return self::SUCCESS;
    }
}
