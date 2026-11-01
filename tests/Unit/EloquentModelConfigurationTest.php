<?php

declare(strict_types=1);

namespace Ronu\AppContext\Tests\Unit;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Ronu\AppContext\Repositories\EloquentClientRepository;
use Ronu\AppContext\Tests\TestCase;

final class EloquentModelConfigurationTest extends TestCase
{
    public function test_model_tables_and_inferred_connection_authenticate_a_stored_client(): void
    {
        $this->exerciseRepository(['app_model' => ClientAppModel::class, 'app_key_model' => ClientKeyModel::class]);
    }

    public function test_explicit_connection_takes_precedence_over_model_connection(): void
    {
        $this->exerciseRepository([
            'app_model' => ClientAppModel::class,
            'app_key_model' => ClientKeyModel::class,
            'connection' => 'testing',
        ], 'testing');
    }

    public function test_table_configuration_without_models_remains_supported(): void
    {
        $this->exerciseRepository([
            'apps_table' => 'custom_apps', 'app_keys_table' => 'custom_keys', 'connection' => 'testing',
        ], 'testing');
    }

    private function exerciseRepository(array $config, string $connection = 'model_connection'): void
    {
        config(['database.connections.model_connection' => config('database.connections.testing')]);
        $db = DB::connection($connection);
        $db->getSchemaBuilder()->create('custom_apps', function (Blueprint $table): void {
            $table->id();
            $table->string('app_code');
            $table->boolean('is_active');
            $table->text('config');
            $table->softDeletes();
        });
        $db->getSchemaBuilder()->create('custom_keys', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('app_id');
            $table->string('key_prefix');
            $table->string('key_hash');
            $table->text('config');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();
        });
        $db->table('custom_apps')->insert([
            'id' => 1, 'app_code' => 'buyer', 'is_active' => true,
            'config' => json_encode(['tenant_id' => 'tenant-one']),
        ]);
        $db->table('custom_keys')->insert([
            'app_id' => 1, 'key_prefix' => 'prefix', 'key_hash' => password_hash('secret', PASSWORD_BCRYPT),
            'config' => json_encode(['capabilities' => ['partner:payments:read']]),
        ]);

        $repository = new EloquentClientRepository($config);
        $client = $repository->findByAppCode('buyer', 'prefix');
        self::assertNotNull($client);
        self::assertSame('tenant-one', $client->tenantId);
        self::assertTrue(password_verify('secret', $client->keyHash));
        self::assertSame(['partner:payments:read'], $client->capabilities);
        self::assertNull($repository->findByAppCode('buyer', 'wrong-prefix'));
        $db->table('custom_keys')->update(['revoked_at' => now()]);
        self::assertNull($repository->findByAppCode('buyer', 'prefix'));
    }
}

final class ClientAppModel extends Model
{
    protected $table = 'custom_apps';
    protected $connection = 'model_connection';
}

final class ClientKeyModel extends Model
{
    protected $table = 'custom_keys';
    protected $connection = 'model_connection';
}
