<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Commands;

use Charlietyn\AppContext\Models\ApiClient;
use Illuminate\Console\Command;

class RevokeApiKeyCommand extends Command
{
    protected $signature = 'app-context:revoke-key
                            {client_id : The client ID (app_code) to revoke}
                            {--force : Skip confirmation}';

    protected $description = 'Revoke an API key';

    public function handle(): int
    {
        $clientId = $this->argument('client_id');

        $client = ApiClient::where('app_code', $clientId)->first();

        if ($client === null) {
            $this->error("Client not found: {$clientId}");

            return self::FAILURE;
        }

        if ($client->is_revoked) {
            $this->warn("Client '{$clientId}' is already revoked.");

            return self::SUCCESS;
        }

        // Show client info
        $this->table(['Field', 'Value'], [
            ['Client ID', $client->app_code],
            ['Name', $client->name],
            ['Channel', $client->channel],
            ['Created', $client->created_at->format('Y-m-d H:i:s')],
            ['Last Used', $client->last_used_at?->format('Y-m-d H:i:s') ?: 'Never'],
        ]);

        // Confirm
        if (! $this->option('force')) {
            if (! $this->confirm('Are you sure you want to revoke this API key?')) {
                $this->info('Operation cancelled.');

                return self::SUCCESS;
            }
        }

        // Revoke
        $client->revoke();

        $this->info("API key for '{$clientId}' has been revoked.");

        return self::SUCCESS;
    }
}
