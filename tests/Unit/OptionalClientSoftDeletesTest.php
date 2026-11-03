<?php

declare(strict_types=1);

namespace Ronu\AppContext\Tests\Unit;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\DataProvider;
use Ronu\AppContext\Repositories\EloquentClientRepository;
use Ronu\AppContext\Tests\TestCase;

final class OptionalClientSoftDeletesTest extends TestCase
{
    public static function schemas(): array
    {
        return [
            'tablas sin borrado lógico' => [false, false],
            'tablas con borrado lógico' => [true, false],
            'modelos sin borrado lógico' => [false, true],
            'modelos con borrado lógico' => [true, true],
        ];
    }

    public static function legacySchemas(): array
    {
        return [[false], [true]];
    }

    #[DataProvider('legacySchemas')]
    public function test_legacy_table_preserves_optional_soft_deletes(bool $softDeletes): void
    {
        $db = DB::connection();
        $db->getSchemaBuilder()->create('api_clients', function (Blueprint $table) use ($softDeletes): void {
            $table->uuid('id')->primary();
            foreach (['name', 'app_code', 'key_hash', 'key_prefix', 'channel'] as $column) $table->string($column);
            foreach (['tenant_id', 'last_used_ip'] as $column) $table->string($column)->nullable();
            $table->json('config')->nullable();
            $table->json('ip_allowlist')->nullable();
            $table->boolean('is_active');
            $table->boolean('is_revoked');
            $table->timestamp('expires_at')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->unsignedBigInteger('usage_count')->default(0);
            $table->timestamps();
            if ($softDeletes) $table->softDeletes();
        });
        $repository = new EloquentClientRepository(['table' => 'api_clients', 'hash_algorithm' => 'bcrypt']);
        $issued = $repository->create(['app_code' => 'legacy', 'name' => 'Legacy']);
        self::assertNotNull($repository->findByAppCode('legacy'));
        self::assertNotNull($repository->findByAppCodeIncludingInactive('legacy'));
        self::assertCount(1, iterator_to_array($repository->all()));
        self::assertTrue($repository->verifyKeyHash($issued->metadata['generated_key'], $repository->findByAppCode('legacy')->keyHash));
        if ($softDeletes) {
            $db->table('api_clients')->update(['deleted_at' => now()]);
            self::assertNull($repository->findByAppCode('legacy'));
            self::assertNull($repository->findByAppCodeIncludingInactive('legacy'));
            self::assertCount(0, iterator_to_array($repository->all(['include_revoked' => true, 'include_inactive' => true])));
        }
    }

    #[DataProvider('schemas')]
    public function test_separate_tables_preserve_client_lifecycle(bool $softDeletes, bool $models): void
    {
        config(['database.connections.clients_test' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']]);
        $db = DB::connection('clients_test');
        $db->getSchemaBuilder()->create('applications', function (Blueprint $table) use ($softDeletes): void {
            $table->id();
            $table->string('app_code')->unique();
            $table->string('app_name');
            $table->string('description')->nullable();
            $table->string('owner_email')->nullable();
            $table->boolean('is_active');
            $table->json('config')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();
            if ($softDeletes) $table->softDeletes();
        });
        $db->getSchemaBuilder()->create('application_keys', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('app_id');
            $table->string('label');
            $table->string('key_prefix');
            $table->string('key_hash');
            $table->text('key_ciphertext')->nullable();
            $table->text('phrase')->nullable();
            $table->text('scopes')->nullable();
            $table->json('config')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->string('last_used_ip')->nullable();
            $table->string('last_user_agent')->nullable();
            $table->timestamps();
        });
        $repository = new EloquentClientRepository([
            ...($models ? ['app_model' => OptionalClientApp::class, 'app_key_model' => OptionalClientKey::class]
                : ['connection' => 'clients_test', 'apps_table' => 'applications', 'app_keys_table' => 'application_keys']),
            'hash_algorithm' => 'bcrypt', 'async_tracking' => false,
        ]);
        $issued = $repository->create(['app_code' => 'bff', 'name' => 'BFF', 'tenant_id' => 'tenant', 'capabilities' => ['partner:payments:create']]);
        $found = $repository->findByAppCode('bff', $issued->keyPrefix);
        self::assertNotNull($found);
        self::assertTrue($repository->verifyKeyHash($issued->metadata['generated_key'], $found->keyHash));
        self::assertSame('tenant', $found->tenantId);
        self::assertSame(['partner:payments:create'], $found->capabilities);
        self::assertCount(1, iterator_to_array($repository->all()));
        $repository->trackUsage('bff', '127.0.0.1', $issued->keyPrefix, 'test');
        self::assertSame('127.0.0.1', $db->table('application_keys')->value('last_used_ip'));

        if ($softDeletes) {
            $db->table('applications')->update(['deleted_at' => now()]);
            self::assertNull($repository->findByAppCode('bff'));
            self::assertNull($repository->findByAppCodeIncludingInactive('bff'));
            self::assertCount(0, iterator_to_array($repository->all(['include_inactive' => true, 'include_revoked' => true])));
            self::assertFalse($repository->revoke('bff'));
            $repository->trackUsage('bff', '127.0.0.2', $issued->keyPrefix);
            self::assertSame('127.0.0.1', $db->table('application_keys')->value('last_used_ip'));
            $db->table('applications')->update(['deleted_at' => null]);
        }

        self::assertTrue($repository->revoke('bff'));
        self::assertNull($repository->findByAppCode('bff'));
        self::assertTrue($repository->findByAppCodeIncludingInactive('bff')->isRevoked);
        self::assertCount(0, iterator_to_array($repository->all()));
    }
}

final class OptionalClientApp extends Model
{
    protected $connection = 'clients_test';
    protected $table = 'applications';
}

final class OptionalClientKey extends Model
{
    protected $connection = 'clients_test';
    protected $table = 'application_keys';
}
