<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Commands;

use Charlietyn\AppContext\Auth\Verifiers\ApiKeyVerifier;
use Charlietyn\AppContext\Models\ApiClient;
use Illuminate\Console\Command;
use Illuminate\Support\Str;

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

    public function handle(ApiKeyVerifier $verifier): int
    {
        $name = $this->argument('name');
        $channel = $this->option('channel');
        $tenantId = $this->option('tenant');
        $capabilities = $this->option('capabilities') ?: ['partner:*'];
        $ipAllowlist = $this->option('ip-allowlist') ?: null;
        $expires = $this->option('expires');

        // Generate app code
        $appCode = Str::slug($name) . '_' . Str::random(8);

        // Generate API key
        $keyData = $verifier->generateKey();

        // Create client
        $client = ApiClient::create([
            'name' => $name,
            'app_code' => $appCode,
            'key_hash' => $keyData['hash'],
            'key_prefix' => $keyData['prefix'],
            'channel' => $channel,
            'tenant_id' => $tenantId,
            'config' => [
                'capabilities' => $capabilities,
                'rate_limit_tier' => 'default',
            ],
            'ip_allowlist' => $ipAllowlist,
            'is_active' => true,
            'is_revoked' => false,
            'expires_at' => $expires ? now()->parse($expires) : null,
            'usage_count' => 0,
        ]);

        $this->info('API Key generated successfully!');
        $this->newLine();

        $this->table(['Field', 'Value'], [
            ['Client ID', $appCode],
            ['API Key', $keyData['key']],
            ['Channel', $channel],
            ['Tenant', $tenantId ?: 'None'],
            ['Capabilities', implode(', ', $capabilities)],
            ['Expires', $expires ?: 'Never'],
        ]);

        $this->newLine();
        $this->warn('⚠️  Save the API Key now! It cannot be retrieved later.');
        $this->newLine();

        $this->line('Usage:');
        $this->line("  curl -H 'X-Client-Id: {$appCode}' -H 'X-Api-Key: {$keyData['key']}' ...");

        return self::SUCCESS;
    }
}
