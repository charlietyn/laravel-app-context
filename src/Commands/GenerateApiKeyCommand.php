<?php

declare(strict_types=1);

namespace Ronu\AppContext\Commands;

use Ronu\AppContext\Contracts\ClientRepositoryInterface;
use Illuminate\Console\Command;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * Generate a new API key for a client.
 *
 * This command works with the configured client repository.
 * Note: ConfigClientRepository does not support creating clients at runtime.
 * Use EloquentClientRepository or a custom implementation for dynamic creation.
 *
 * @package Ronu\AppContext\Commands
 */
class GenerateApiKeyCommand extends Command
{
    protected $signature = 'app-context:generate-key
                            {name : Client name}
                            {--channel=partner : Channel for the client}
                            {--tenant= : Tenant ID restriction}
                            {--capabilities=* : Capabilities to grant}
                            {--ip-allowlist=* : IP allowlist (supports CIDR)}
                            {--expires= : Expiration date (Y-m-d)}';

    protected $description = 'Generate a new API key for a client';

    public function handle(ClientRepositoryInterface $repository): int
    {
        $name = $this->argument('name');
        $channel = $this->option('channel');
        $tenantId = $this->option('tenant');
        $capabilities = $this->option('capabilities') ?: ['partner:*'];
        $ipAllowlist = $this->option('ip-allowlist') ?: null;
        $expires = $this->option('expires');

        // Generate app code
        $appCode = Str::slug($name) . '_' . Str::random(8);

        try {
            // Create client via repository
            $client = $repository->create([
                'name' => $name,
                'app_code' => $appCode,
                'channel' => $channel,
                'tenant_id' => $tenantId,
                'capabilities' => $capabilities,
                'ip_allowlist' => $ipAllowlist,
                'is_active' => true,
                'expires_at' => $expires ? now()->parse($expires) : null,
            ]);

            // Get the generated key from metadata (if available)
            $generatedKey = $client->getMeta('generated_key');

            $this->info('API Key generated successfully!');
            $this->newLine();

            $this->table(['Field', 'Value'], [
                ['Client ID', $client->appCode],
                ['API Key', $generatedKey ?: '(not returned by repository)'],
                ['Channel', $client->channel],
                ['Tenant', $client->tenantId ?: 'None'],
                ['Capabilities', implode(', ', $client->capabilities)],
                ['Expires', $expires ?: 'Never'],
            ]);

            $this->newLine();

            if ($generatedKey) {
                $this->warn('⚠️  Save the API Key now! It cannot be retrieved later.');
                $this->newLine();

                $this->line('Usage:');
                $this->line("  curl -H 'X-Client-Id: {$client->appCode}' -H 'X-Api-Key: {$generatedKey}' ...");
            }

            return self::SUCCESS;

        } catch (RuntimeException $e) {
            // Handle ConfigClientRepository not supporting creation
            $this->error('Failed to create client: ' . $e->getMessage());
            $this->newLine();

            $driver = config('app-context.client_repository.driver', 'config');

            if ($driver === 'config') {
                $this->warn('The current driver is "config" which does not support runtime client creation.');
                $this->newLine();
                $this->info('To add a client, generate a key hash and add it to your configuration:');
                $this->newLine();

                // Generate key data for manual configuration
                $keyData = $repository->generateKey();

                $this->line('1. Add the following to config/app-context.php under client_repository.config.clients:');
                $this->newLine();
                $this->line("   '{$appCode}' => [");
                $this->line("       'name' => '{$name}',");
                $this->line("       'key_hash' => '{$keyData['hash']}',");
                $this->line("       'channel' => '{$channel}',");
                $this->line("       'tenant_id' => " . ($tenantId ? "'{$tenantId}'" : 'null') . ',');
                $this->line("       'capabilities' => ['" . implode("', '", $capabilities) . "'],");
                $this->line('       ' . "'ip_allowlist' => " . ($ipAllowlist ? "['" . implode("', '", $ipAllowlist) . "']" : '[]') . ',');
                $this->line("       'is_active' => true,");
                $this->line("       'is_revoked' => false,");
                $this->line("       'expires_at' => " . ($expires ? "'{$expires}'" : 'null') . ',');
                $this->line('   ],');
                $this->newLine();
                $this->line('2. Your API Key (save this now!):');
                $this->warn("   {$keyData['key']}");
                $this->newLine();
                $this->info('Alternatively, switch to "eloquent" driver:');
                $this->line('   APP_CONTEXT_CLIENT_DRIVER=eloquent');
                $this->line('   php artisan vendor:publish --tag=app-context-migrations');
                $this->line('   php artisan migrate');

                return self::SUCCESS;
            }

            return self::FAILURE;
        }
    }
}
