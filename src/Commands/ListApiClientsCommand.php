<?php

declare(strict_types=1);

namespace Ronu\AppContext\Commands;

use Ronu\AppContext\Contracts\ClientRepositoryInterface;
use Ronu\AppContext\Support\ClientInfo;
use Illuminate\Console\Command;
use RuntimeException;

/**
 * List all API clients.
 *
 * This command works with the configured client repository.
 *
 * @package Ronu\AppContext\Commands
 */
class ListApiClientsCommand extends Command
{
    protected $signature = 'app-context:list-clients
                            {--channel= : Filter by channel}
                            {--tenant= : Filter by tenant}
                            {--include-revoked : Include revoked clients}';

    protected $description = 'List all API clients';

    public function handle(ClientRepositoryInterface $repository): int
    {
        try {
            $filters = [
                'include_revoked' => $this->option('include-revoked'),
            ];

            if ($channel = $this->option('channel')) {
                $filters['channel'] = $channel;
            }

            if ($tenant = $this->option('tenant')) {
                $filters['tenant'] = $tenant;
            }

            $clients = $repository->all($filters);

            // Convert to array for counting
            $clientsArray = [];
            foreach ($clients as $client) {
                $clientsArray[] = $client;
            }

            if (empty($clientsArray)) {
                $this->info('No API clients found.');

                return self::SUCCESS;
            }

            $rows = array_map(fn (ClientInfo $client) => [
                $client->appCode,
                $client->name,
                $client->channel,
                $client->tenantId ?: '-',
                $client->isActive ? '✓' : '✗',
                $client->isRevoked ? '✓' : '✗',
                $client->expiresAt?->format('Y-m-d') ?: 'Never',
                $client->getMeta('last_used_at') ? (new \DateTime($client->getMeta('last_used_at')))->format('Y-m-d H:i') : 'Never',
                number_format($client->getMeta('usage_count', 0)),
            ], $clientsArray);

            $this->table(
                ['Client ID', 'Name', 'Channel', 'Tenant', 'Active', 'Revoked', 'Expires', 'Last Used', 'Usage'],
                $rows
            );

            return self::SUCCESS;

        } catch (RuntimeException $e) {
            $this->error('Failed to list clients: ' . $e->getMessage());

            $driver = config('app-context.client_repository.driver', 'config');

            if ($driver === 'config') {
                $this->newLine();
                $this->info('Clients defined in configuration:');
                $this->newLine();

                $configClients = config('app-context.client_repository.config.clients', []);

                if (empty($configClients)) {
                    $this->warn('No clients configured. Add clients to config/app-context.php');
                    return self::SUCCESS;
                }

                $rows = [];
                foreach ($configClients as $appCode => $data) {
                    $client = ClientInfo::fromArray(['app_code' => $appCode, ...$data]);

                    // Apply filters
                    if (isset($filters['channel']) && $client->channel !== $filters['channel']) {
                        continue;
                    }
                    if (isset($filters['tenant']) && $client->tenantId !== $filters['tenant']) {
                        continue;
                    }
                    if (!($filters['include_revoked'] ?? false) && $client->isRevoked) {
                        continue;
                    }

                    $rows[] = [
                        $client->appCode,
                        $client->name,
                        $client->channel,
                        $client->tenantId ?: '-',
                        $client->isActive ? '✓' : '✗',
                        $client->isRevoked ? '✓' : '✗',
                        $client->expiresAt?->format('Y-m-d') ?: 'Never',
                        'N/A',
                        'N/A',
                    ];
                }

                if (empty($rows)) {
                    $this->warn('No clients match the specified filters.');
                    return self::SUCCESS;
                }

                $this->table(
                    ['Client ID', 'Name', 'Channel', 'Tenant', 'Active', 'Revoked', 'Expires', 'Last Used', 'Usage'],
                    $rows
                );
            }

            return self::SUCCESS;
        }
    }
}
