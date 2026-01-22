<?php

declare(strict_types=1);

namespace Ronu\AppContext\Commands;

use Ronu\AppContext\Contracts\ClientRepositoryInterface;
use Ronu\AppContext\Repositories\EloquentClientRepository;
use Illuminate\Console\Command;
use RuntimeException;

/**
 * Revoke an API key.
 *
 * This command works with the configured client repository.
 * Note: ConfigClientRepository does not support revoking clients at runtime.
 *
 * @package Ronu\AppContext\Commands
 */
class RevokeApiKeyCommand extends Command
{
    protected $signature = 'app-context:revoke-key
                            {client_id : The client ID (app_code) to revoke}
                            {--force : Skip confirmation}';

    protected $description = 'Revoke an API key';

    public function handle(ClientRepositoryInterface $repository): int
    {
        $clientId = $this->argument('client_id');

        // Try to find client for display
        $client = null;

        // Use specialized method if available (EloquentClientRepository)
        if ($repository instanceof EloquentClientRepository) {
            $client = $repository->findByAppCodeIncludingInactive($clientId);
        } else {
            $client = $repository->findByAppCode($clientId);
        }

        if ($client === null) {
            $this->error("Client not found: {$clientId}");

            return self::FAILURE;
        }

        if ($client->isRevoked) {
            $this->warn("Client '{$clientId}' is already revoked.");

            return self::SUCCESS;
        }

        // Show client info
        $this->table(['Field', 'Value'], [
            ['Client ID', $client->appCode],
            ['Name', $client->name],
            ['Channel', $client->channel],
            ['Created', $client->getMeta('created_at') ?: 'Unknown'],
            ['Last Used', $client->getMeta('last_used_at') ?: 'Never'],
        ]);

        // Confirm
        if (!$this->option('force')) {
            if (!$this->confirm('Are you sure you want to revoke this API key?')) {
                $this->info('Operation cancelled.');

                return self::SUCCESS;
            }
        }

        try {
            // Revoke via repository
            $success = $repository->revoke($clientId);

            if ($success) {
                $this->info("API key for '{$clientId}' has been revoked.");
                return self::SUCCESS;
            }

            $this->error("Failed to revoke API key for '{$clientId}'.");
            return self::FAILURE;

        } catch (RuntimeException $e) {
            $this->error('Failed to revoke client: ' . $e->getMessage());

            $driver = config('app-context.client_repository.driver', 'config');

            if ($driver === 'config') {
                $this->newLine();
                $this->warn('The "config" driver does not support revoking clients at runtime.');
                $this->info('To revoke a client, edit config/app-context.php and set:');
                $this->newLine();
                $this->line("   '{$clientId}' => [");
                $this->line("       ...");
                $this->line("       'is_revoked' => true,  // Add or change this");
                $this->line('   ],');
                $this->newLine();
                $this->info('Or switch to "eloquent" driver for dynamic management:');
                $this->line('   APP_CONTEXT_CLIENT_DRIVER=eloquent');
            }

            return self::FAILURE;
        }
    }
}
