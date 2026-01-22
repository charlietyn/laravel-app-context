<?php

declare(strict_types=1);

namespace Ronu\AppContext\Tests\Unit;

use Ronu\AppContext\Contracts\ClientRepositoryInterface;
use Ronu\AppContext\Repositories\ConfigClientRepository;
use Ronu\AppContext\Repositories\EloquentClientRepository;
use Ronu\AppContext\Support\ClientInfo;
use Ronu\AppContext\Tests\TestCase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use RuntimeException;

class ClientRepositoryTest extends TestCase
{
    /*
    |--------------------------------------------------------------------------
    | ClientInfo Tests
    |--------------------------------------------------------------------------
    */

    public function test_client_info_from_array(): void
    {
        $data = [
            'app_code' => 'test-client',
            'name' => 'Test Client',
            'key_hash' => 'hashed-key',
            'channel' => 'partner',
            'tenant_id' => 'tenant-1',
            'capabilities' => ['partner:*', 'webhooks:read'],
            'ip_allowlist' => ['192.168.1.0/24'],
            'is_active' => true,
            'is_revoked' => false,
            'expires_at' => '2030-12-31 23:59:59',
            'metadata' => ['rate_limit_tier' => 'premium'],
        ];

        $client = ClientInfo::fromArray($data);

        $this->assertSame('test-client', $client->appCode);
        $this->assertSame('Test Client', $client->name);
        $this->assertSame('hashed-key', $client->keyHash);
        $this->assertSame('partner', $client->channel);
        $this->assertSame('tenant-1', $client->tenantId);
        $this->assertSame(['partner:*', 'webhooks:read'], $client->capabilities);
        $this->assertSame(['192.168.1.0/24'], $client->ipAllowlist);
        $this->assertTrue($client->isActive);
        $this->assertFalse($client->isRevoked);
        $this->assertNotNull($client->expiresAt);
        $this->assertSame('premium', $client->getMeta('rate_limit_tier'));
    }

    public function test_client_info_is_valid(): void
    {
        $validClient = ClientInfo::fromArray([
            'app_code' => 'valid-client',
            'name' => 'Valid Client',
            'key_hash' => 'hash',
            'channel' => 'partner',
            'is_active' => true,
            'is_revoked' => false,
        ]);

        $this->assertTrue($validClient->isValid());

        $revokedClient = ClientInfo::fromArray([
            'app_code' => 'revoked-client',
            'name' => 'Revoked Client',
            'key_hash' => 'hash',
            'channel' => 'partner',
            'is_active' => true,
            'is_revoked' => true,
        ]);

        $this->assertFalse($revokedClient->isValid());

        $expiredClient = ClientInfo::fromArray([
            'app_code' => 'expired-client',
            'name' => 'Expired Client',
            'key_hash' => 'hash',
            'channel' => 'partner',
            'is_active' => true,
            'is_revoked' => false,
            'expires_at' => '2020-01-01 00:00:00',
        ]);

        $this->assertFalse($expiredClient->isValid());
    }

    public function test_client_info_has_capability(): void
    {
        $client = ClientInfo::fromArray([
            'app_code' => 'test',
            'name' => 'Test',
            'key_hash' => 'hash',
            'channel' => 'partner',
            'capabilities' => ['partner:orders:*', 'inventory:read'],
        ]);

        $this->assertTrue($client->hasCapability('partner:orders:create'));
        $this->assertTrue($client->hasCapability('partner:orders:read'));
        $this->assertTrue($client->hasCapability('inventory:read'));
        $this->assertFalse($client->hasCapability('inventory:write'));
        $this->assertFalse($client->hasCapability('admin:*'));
    }

    public function test_client_info_to_array(): void
    {
        $client = ClientInfo::fromArray([
            'app_code' => 'test',
            'name' => 'Test',
            'key_hash' => 'hash',
            'channel' => 'partner',
        ]);

        $array = $client->toArray();

        $this->assertArrayHasKey('app_code', $array);
        $this->assertArrayHasKey('name', $array);
        $this->assertArrayHasKey('channel', $array);
        $this->assertSame('test', $array['app_code']);
    }

    /*
    |--------------------------------------------------------------------------
    | ConfigClientRepository Tests
    |--------------------------------------------------------------------------
    */

    public function test_config_repository_find_by_app_code(): void
    {
        $repository = new ConfigClientRepository([
            'hash_algorithm' => 'bcrypt',
            'clients' => [
                'test-client' => [
                    'name' => 'Test Client',
                    'key_hash' => Hash::make('secret-key'),
                    'channel' => 'partner',
                    'capabilities' => ['partner:*'],
                ],
            ],
        ]);

        $client = $repository->findByAppCode('test-client');

        $this->assertNotNull($client);
        $this->assertSame('test-client', $client->appCode);
        $this->assertSame('Test Client', $client->name);
        $this->assertSame('partner', $client->channel);
    }

    public function test_config_repository_returns_null_for_unknown_client(): void
    {
        $repository = new ConfigClientRepository([
            'clients' => [],
        ]);

        $this->assertNull($repository->findByAppCode('nonexistent'));
    }

    public function test_config_repository_returns_null_for_inactive_client(): void
    {
        $repository = new ConfigClientRepository([
            'clients' => [
                'inactive-client' => [
                    'name' => 'Inactive',
                    'key_hash' => 'hash',
                    'channel' => 'partner',
                    'is_active' => false,
                ],
            ],
        ]);

        $this->assertNull($repository->findByAppCode('inactive-client'));
    }

    public function test_config_repository_verify_key_hash(): void
    {
        $repository = new ConfigClientRepository([
            'hash_algorithm' => 'bcrypt',
        ]);

        $hash = Hash::make('test-key');

        $this->assertTrue($repository->verifyKeyHash('test-key', $hash));
        $this->assertFalse($repository->verifyKeyHash('wrong-key', $hash));
    }

    public function test_config_repository_generate_key(): void
    {
        $repository = new ConfigClientRepository([
            'hash_algorithm' => 'bcrypt',
            'prefix_length' => 10,
            'key_length' => 32,
        ]);

        $keyData = $repository->generateKey();

        $this->assertArrayHasKey('key', $keyData);
        $this->assertArrayHasKey('hash', $keyData);
        $this->assertArrayHasKey('prefix', $keyData);
        $this->assertStringContainsString('.', $keyData['key']);
        $this->assertSame(10, strlen($keyData['prefix']));
    }

    public function test_config_repository_track_usage_is_noop(): void
    {
        $repository = new ConfigClientRepository([]);

        // Should not throw any exception
        $repository->trackUsage('test-client', '127.0.0.1');
        $this->assertTrue(true);
    }

    public function test_config_repository_create_throws_exception(): void
    {
        $repository = new ConfigClientRepository([]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('does not support creating clients');

        $repository->create(['name' => 'Test']);
    }

    public function test_config_repository_revoke_throws_exception(): void
    {
        $repository = new ConfigClientRepository([]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('does not support revoking clients');

        $repository->revoke('test-client');
    }

    public function test_config_repository_all(): void
    {
        $repository = new ConfigClientRepository([
            'clients' => [
                'client-1' => [
                    'name' => 'Client 1',
                    'key_hash' => 'hash1',
                    'channel' => 'partner',
                    'is_active' => true,
                ],
                'client-2' => [
                    'name' => 'Client 2',
                    'key_hash' => 'hash2',
                    'channel' => 'admin',
                    'is_active' => true,
                ],
                'client-3' => [
                    'name' => 'Client 3',
                    'key_hash' => 'hash3',
                    'channel' => 'partner',
                    'is_revoked' => true,
                ],
            ],
        ]);

        // All active, non-revoked
        $clients = iterator_to_array($repository->all());
        $this->assertCount(2, $clients);

        // Filter by channel
        $partnerClients = iterator_to_array($repository->all(['channel' => 'partner']));
        $this->assertCount(1, $partnerClients);

        // Include revoked
        $allWithRevoked = iterator_to_array($repository->all(['include_revoked' => true]));
        $this->assertCount(3, $allWithRevoked);
    }

    /*
    |--------------------------------------------------------------------------
    | EloquentClientRepository Tests
    |--------------------------------------------------------------------------
    */

    protected function setUpDatabase(): void
    {
        // Create the api_clients table for testing
        if (!$this->app['db']->getSchemaBuilder()->hasTable('api_clients')) {
            $this->app['db']->getSchemaBuilder()->create('api_clients', function ($table) {
                $table->uuid('id')->primary();
                $table->string('name');
                $table->string('app_code')->unique();
                $table->string('key_hash');
                $table->string('key_prefix', 20)->nullable();
                $table->string('channel')->default('partner');
                $table->string('tenant_id')->nullable();
                $table->json('config')->nullable();
                $table->json('ip_allowlist')->nullable();
                $table->boolean('is_active')->default(true);
                $table->boolean('is_revoked')->default(false);
                $table->timestamp('expires_at')->nullable();
                $table->timestamp('last_used_at')->nullable();
                $table->string('last_used_ip', 45)->nullable();
                $table->unsignedBigInteger('usage_count')->default(0);
                $table->timestamps();
                $table->softDeletes();
            });
        }
    }

    public function test_eloquent_repository_find_by_app_code(): void
    {
        $this->setUpDatabase();

        $repository = new EloquentClientRepository([
            'table' => 'api_clients',
            'hash_algorithm' => 'bcrypt',
        ]);

        // Insert test data
        DB::table('api_clients')->insert([
            'id' => (string) \Illuminate\Support\Str::uuid(),
            'name' => 'Test Client',
            'app_code' => 'eloquent-test-client',
            'key_hash' => Hash::make('secret-key'),
            'channel' => 'partner',
            'config' => json_encode(['capabilities' => ['partner:*']]),
            'is_active' => true,
            'is_revoked' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $client = $repository->findByAppCode('eloquent-test-client');

        $this->assertNotNull($client);
        $this->assertSame('eloquent-test-client', $client->appCode);
        $this->assertSame('Test Client', $client->name);
        $this->assertSame(['partner:*'], $client->capabilities);
    }

    public function test_eloquent_repository_create(): void
    {
        $this->setUpDatabase();

        $repository = new EloquentClientRepository([
            'table' => 'api_clients',
            'hash_algorithm' => 'bcrypt',
        ]);

        $client = $repository->create([
            'name' => 'New Client',
            'channel' => 'partner',
            'capabilities' => ['partner:orders:*'],
        ]);

        $this->assertNotNull($client->appCode);
        $this->assertSame('New Client', $client->name);
        $this->assertSame('partner', $client->channel);
        $this->assertNotNull($client->getMeta('generated_key'));

        // Verify it was saved
        $found = $repository->findByAppCode($client->appCode);
        $this->assertNotNull($found);
    }

    public function test_eloquent_repository_revoke(): void
    {
        $this->setUpDatabase();

        $repository = new EloquentClientRepository([
            'table' => 'api_clients',
            'hash_algorithm' => 'bcrypt',
        ]);

        $client = $repository->create([
            'name' => 'To Revoke',
            'channel' => 'partner',
        ]);

        // First verify client exists and is not revoked
        $foundBefore = $repository->findByAppCodeIncludingInactive($client->appCode);
        $this->assertNotNull($foundBefore);
        $this->assertFalse($foundBefore->isRevoked);

        $success = $repository->revoke($client->appCode);
        $this->assertTrue($success);

        // findByAppCode filters by is_active=true, but revoke only sets is_revoked=true
        // So the client should still be "found" but marked as revoked
        $foundAfter = $repository->findByAppCodeIncludingInactive($client->appCode);
        $this->assertNotNull($foundAfter);
        $this->assertTrue($foundAfter->isRevoked);
    }

    public function test_eloquent_repository_all(): void
    {
        $this->setUpDatabase();

        // Delete all existing records instead of truncate (SQLite compatibility)
        DB::table('api_clients')->delete();

        $repository = new EloquentClientRepository([
            'table' => 'api_clients',
            'hash_algorithm' => 'bcrypt',
        ]);

        // Create multiple clients
        $repository->create(['name' => 'Client A', 'channel' => 'partner']);
        $repository->create(['name' => 'Client B', 'channel' => 'admin']);
        $repository->create(['name' => 'Client C', 'channel' => 'partner']);

        $allClients = iterator_to_array($repository->all());
        $this->assertCount(3, $allClients);

        $partnerClients = iterator_to_array($repository->all(['channel' => 'partner']));
        $this->assertCount(2, $partnerClients);
    }

    /*
    |--------------------------------------------------------------------------
    | Service Provider Integration Tests
    |--------------------------------------------------------------------------
    */

    public function test_config_driver_resolves_correctly(): void
    {
        config(['app-context.client_repository.driver' => 'config']);
        config(['app-context.client_repository.config.clients' => [
            'test' => ['name' => 'Test', 'key_hash' => 'hash', 'channel' => 'partner'],
        ]]);

        // Clear singleton
        $this->app->forgetInstance(ClientRepositoryInterface::class);

        $repository = $this->app->make(ClientRepositoryInterface::class);

        $this->assertInstanceOf(ConfigClientRepository::class, $repository);
    }

    public function test_eloquent_driver_resolves_correctly(): void
    {
        config(['app-context.client_repository.driver' => 'eloquent']);

        // Clear singleton
        $this->app->forgetInstance(ClientRepositoryInterface::class);

        $repository = $this->app->make(ClientRepositoryInterface::class);

        $this->assertInstanceOf(EloquentClientRepository::class, $repository);
    }
}
