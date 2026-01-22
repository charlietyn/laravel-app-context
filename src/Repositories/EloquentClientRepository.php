<?php

declare(strict_types=1);

namespace Ronu\AppContext\Repositories;

use Ronu\AppContext\Contracts\ClientRepositoryInterface;
use Ronu\AppContext\Support\ClientInfo;
use DateTimeImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * Eloquent/Database-based client repository.
 *
 * This implementation uses direct database queries (not a specific model),
 * allowing users to use any table structure that matches the expected schema.
 *
 * Required columns (legacy single-table):
 * - app_code (string, unique)
 * - name (string)
 * - key_hash (string)
 * - channel (string)
 * - tenant_id (string, nullable)
 * - config (json) with 'capabilities' key
 * - ip_allowlist (json, nullable)
 * - is_active (boolean)
 * - is_revoked (boolean)
 * - expires_at (timestamp, nullable)
 *
 * Optional columns for tracking (legacy):
 * - last_used_at (timestamp)
 * - last_used_ip (string)
 * - usage_count (integer)
 *
 * Multi-table schema (recommended):
 * - api_apps (clients)
 * - api_app_keys (keys per app)
 *
 * @package Ronu\AppContext\Repositories
 */
final class EloquentClientRepository implements ClientRepositoryInterface
{
    /**
     * @var string Database table name
     */
    private readonly string $table;

    /**
     * @var string|null Database connection name
     */
    private readonly ?string $connection;

    /**
     * @var string Database table name for apps
     */
    private readonly string $appsTable;

    /**
     * @var string Database table name for app keys
     */
    private readonly string $appKeysTable;

    /**
     * @var string|null Eloquent model class for apps
     */
    private readonly ?string $appModelClass;

    /**
     * @var string|null Eloquent model class for app keys
     */
    private readonly ?string $appKeyModelClass;

    /**
     * @var bool Whether to use the multi-table schema
     */
    private readonly bool $useSeparateKeysTable;

    /**
     * @var string Hash algorithm
     */
    private readonly string $hashAlgorithm;

    /**
     * @var int Key prefix length
     */
    private readonly int $prefixLength;

    /**
     * @var int Key secret length
     */
    private readonly int $keyLength;

    /**
     * @var bool Whether to track usage asynchronously
     */
    private readonly bool $asyncTracking;

    /**
     * @param array<string, mixed> $config Repository configuration
     */
    public function __construct(array $config)
    {
        $this->appModelClass = $config['app_model'] ?? null;
        $this->appKeyModelClass = $config['app_key_model'] ?? null;
        $this->table = $config['table'] ?? 'api_clients';
        $this->appsTable = $config['apps_table'] ?? 'api_apps';
        $this->appKeysTable = $config['app_keys_table'] ?? 'api_app_keys';
        $this->connection = $config['connection'] ?? null;
        $this->hashAlgorithm = $config['hash_algorithm'] ?? 'argon2id';
        $this->prefixLength = $config['prefix_length'] ?? 10;
        $this->keyLength = $config['key_length'] ?? 32;
        $this->asyncTracking = $config['async_tracking'] ?? true;
        $this->useSeparateKeysTable = $this->appModelClass !== null
            || $this->appKeyModelClass !== null
            || isset($config['apps_table'])
            || isset($config['app_keys_table']);

        if ($this->appModelClass !== null) {
            $appModel = $this->instantiateModel($this->appModelClass);
            $this->appsTable = $appModel->getTable();
            $this->connection ??= $appModel->getConnectionName();
        }

        if ($this->appKeyModelClass !== null) {
            $keyModel = $this->instantiateModel($this->appKeyModelClass);
            $this->appKeysTable = $keyModel->getTable();
            $this->connection ??= $keyModel->getConnectionName();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function findByAppCode(string $appCode, ?string $keyPrefix = null): ?ClientInfo
    {
        if ($this->useSeparateKeysTable) {
            $appRecord = $this->appQuery()
                ->where('app_code', $appCode)
                ->where('is_active', true)
                ->whereNull('deleted_at')
                ->first();

            if ($appRecord === null) {
                return null;
            }

            $keyQuery = $this->appKeyQuery()
                ->where('app_id', $appRecord->id)
                ->whereNull('revoked_at');

            if ($keyPrefix !== null) {
                $keyQuery->where('key_prefix', $keyPrefix);
            }

            $keyRecord = $keyQuery
                ->orderBy('created_at', 'desc')
                ->first();

            if ($keyRecord === null) {
                return null;
            }

            return $this->toClientInfo($appRecord, $keyRecord);
        }

        $record = $this->query()
            ->where('app_code', $appCode)
            ->where('is_active', true)
            ->whereNull('deleted_at')
            ->first();

        if ($record === null) {
            return null;
        }

        return $this->toClientInfo($record);
    }

    /**
     * {@inheritdoc}
     */
    public function verifyKeyHash(string $key, string $storedHash): bool
    {
        return match ($this->hashAlgorithm) {
            'argon2id' => password_verify($key, $storedHash),
            'bcrypt' => Hash::check($key, $storedHash),
            default => Hash::check($key, $storedHash),
        };
    }

    /**
     * {@inheritdoc}
     */
    public function trackUsage(
        string $appCode,
        string $ip,
        ?string $keyPrefix = null,
        ?string $userAgent = null
    ): void
    {
        $updateFn = function () use ($appCode, $ip, $keyPrefix, $userAgent) {
            if ($this->useSeparateKeysTable) {
                $appRecord = $this->appQuery()
                    ->where('app_code', $appCode)
                    ->whereNull('deleted_at')
                    ->first();

                if ($appRecord === null || $keyPrefix === null) {
                    return;
                }

                $this->appKeyQuery()
                    ->where('app_id', $appRecord->id)
                    ->where('key_prefix', $keyPrefix)
                    ->update([
                        'last_used_at' => now(),
                        'last_used_ip' => $ip,
                        'last_user_agent' => $userAgent,
                    ]);

                return;
            }

            $this->query()
                ->where('app_code', $appCode)
                ->update([
                    'last_used_at' => now(),
                    'last_used_ip' => $ip,
                    'usage_count' => DB::raw('COALESCE(usage_count, 0) + 1'),
                ]);
        };

        if ($this->asyncTracking) {
            dispatch($updateFn)->afterResponse();
        } else {
            $updateFn();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function generateKey(): array
    {
        $prefix = Str::random($this->prefixLength);
        $secret = Str::random($this->keyLength);
        $key = "{$prefix}.{$secret}";

        return [
            'key' => $key,
            'hash' => $this->hashKey($key),
            'prefix' => $prefix,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function create(array $data): ClientInfo
    {
        if ($this->useSeparateKeysTable) {
            return $this->createUsingSeparateTables($data);
        }

        $keyData = $this->generateKey();

        $id = (string) Str::uuid();
        $now = now();

        $record = [
            'id' => $id,
            'name' => $data['name'],
            'app_code' => $data['app_code'] ?? Str::slug($data['name']) . '_' . Str::random(8),
            'key_hash' => $keyData['hash'],
            'key_prefix' => $keyData['prefix'],
            'channel' => $data['channel'] ?? 'partner',
            'tenant_id' => $data['tenant_id'] ?? null,
            'config' => json_encode([
                'capabilities' => $data['capabilities'] ?? ['partner:*'],
                'rate_limit_tier' => $data['rate_limit_tier'] ?? 'default',
                'webhook_url' => $data['webhook_url'] ?? null,
            ]),
            'ip_allowlist' => isset($data['ip_allowlist']) ? json_encode($data['ip_allowlist']) : null,
            'is_active' => $data['is_active'] ?? true,
            'is_revoked' => false,
            'expires_at' => $data['expires_at'] ?? null,
            'last_used_at' => null,
            'last_used_ip' => null,
            'usage_count' => 0,
            'created_at' => $now,
            'updated_at' => $now,
        ];

        $this->query()->insert($record);

        $clientInfo = $this->toClientInfo((object) $record);

        // Add generated key to metadata for command output
        return new ClientInfo(
            appCode: $clientInfo->appCode,
            name: $clientInfo->name,
            keyHash: $clientInfo->keyHash,
            channel: $clientInfo->channel,
            tenantId: $clientInfo->tenantId,
            capabilities: $clientInfo->capabilities,
            ipAllowlist: $clientInfo->ipAllowlist,
            isActive: $clientInfo->isActive,
            isRevoked: $clientInfo->isRevoked,
            expiresAt: $clientInfo->expiresAt,
            metadata: [
                ...$clientInfo->metadata,
                'generated_key' => $keyData['key'],
            ],
            id: $clientInfo->id,
            keyPrefix: $clientInfo->keyPrefix,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(string $appCode): bool
    {
        if ($this->useSeparateKeysTable) {
            return $this->revokeUsingSeparateTables($appCode);
        }

        $affected = $this->query()
            ->where('app_code', $appCode)
            ->update([
                'is_revoked' => true,
                'updated_at' => now(),
            ]);

        return $affected > 0;
    }

    /**
     * {@inheritdoc}
     */
    public function all(array $filters = []): iterable
    {
        if ($this->useSeparateKeysTable) {
            yield from $this->allUsingSeparateTables($filters);

            return;
        }

        $query = $this->query()->whereNull('deleted_at');

        if (isset($filters['channel'])) {
            $query->where('channel', $filters['channel']);
        }

        if (isset($filters['tenant'])) {
            $query->where('tenant_id', $filters['tenant']);
        }

        if (!($filters['include_revoked'] ?? false)) {
            $query->where('is_revoked', false);
        }

        if (!($filters['include_inactive'] ?? false)) {
            $query->where('is_active', true);
        }

        $query->orderBy('created_at', 'desc');

        foreach ($query->cursor() as $record) {
            yield $this->toClientInfo($record);
        }
    }

    /**
     * Find a client by app_code regardless of status (for commands).
     */
    public function findByAppCodeIncludingInactive(string $appCode): ?ClientInfo
    {
        if ($this->useSeparateKeysTable) {
            $appRecord = $this->appQuery()
                ->where('app_code', $appCode)
                ->whereNull('deleted_at')
                ->first();

            if ($appRecord === null) {
                return null;
            }

            $keyRecord = $this->appKeyQuery()
                ->where('app_id', $appRecord->id)
                ->orderBy('created_at', 'desc')
                ->first();

            if ($keyRecord === null) {
                return null;
            }

            return $this->toClientInfo($appRecord, $keyRecord);
        }

        $record = $this->query()
            ->where('app_code', $appCode)
            ->whereNull('deleted_at')
            ->first();

        if ($record === null) {
            return null;
        }

        return $this->toClientInfo($record);
    }

    /**
     * Get the database query builder.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function query()
    {
        $query = DB::table($this->table);

        if ($this->connection !== null) {
            $query = DB::connection($this->connection)->table($this->table);
        }

        return $query;
    }

    /**
     * Get the database query builder for apps.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function appQuery()
    {
        $query = DB::table($this->appsTable);

        if ($this->connection !== null) {
            $query = DB::connection($this->connection)->table($this->appsTable);
        }

        return $query;
    }

    /**
     * Get the database query builder for app keys.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function appKeyQuery()
    {
        $query = DB::table($this->appKeysTable);

        if ($this->connection !== null) {
            $query = DB::connection($this->connection)->table($this->appKeysTable);
        }

        return $query;
    }

    /**
     * Convert database record to ClientInfo.
     */
    private function toClientInfo(object $record, ?object $keyRecord = null): ClientInfo
    {
        if ($this->useSeparateKeysTable && $keyRecord !== null) {
            return $this->toClientInfoFromSeparateTables($record, $keyRecord);
        }

        $config = is_string($record->config)
            ? json_decode($record->config, true)
            : (array) ($record->config ?? []);

        $ipAllowlist = is_string($record->ip_allowlist ?? null)
            ? json_decode($record->ip_allowlist, true)
            : (array) ($record->ip_allowlist ?? []);

        $expiresAt = null;
        if (isset($record->expires_at) && $record->expires_at !== null) {
            $expiresAt = $record->expires_at instanceof \DateTimeInterface
                ? $record->expires_at
                : new DateTimeImmutable($record->expires_at);
        }

        return new ClientInfo(
            appCode: $record->app_code,
            name: $record->name,
            keyHash: $record->key_hash,
            channel: $record->channel,
            tenantId: $record->tenant_id ?? null,
            capabilities: $config['capabilities'] ?? [],
            ipAllowlist: $ipAllowlist,
            isActive: (bool) $record->is_active,
            isRevoked: (bool) $record->is_revoked,
            expiresAt: $expiresAt,
            metadata: [
                'rate_limit_tier' => $config['rate_limit_tier'] ?? 'default',
                'webhook_url' => $config['webhook_url'] ?? null,
                'last_used_at' => $record->last_used_at ?? null,
                'last_used_ip' => $record->last_used_ip ?? null,
                'usage_count' => $record->usage_count ?? 0,
                'created_at' => $record->created_at ?? null,
            ],
            id: $record->id ?? null,
            keyPrefix: $record->key_prefix ?? null,
        );
    }

    /**
     * Convert separate app + key records to ClientInfo.
     */
    private function toClientInfoFromSeparateTables(object $appRecord, object $keyRecord): ClientInfo
    {
        $appConfig = is_string($appRecord->config)
            ? json_decode($appRecord->config, true)
            : (array) ($appRecord->config ?? []);

        $appMetadata = is_string($appRecord->metadata ?? null)
            ? json_decode($appRecord->metadata, true)
            : (array) ($appRecord->metadata ?? []);

        $keyConfig = is_string($keyRecord->config)
            ? json_decode($keyRecord->config, true)
            : (array) ($keyRecord->config ?? []);

        $expiresAt = null;
        if (isset($keyRecord->expires_at) && $keyRecord->expires_at !== null) {
            $expiresAt = $keyRecord->expires_at instanceof \DateTimeInterface
                ? $keyRecord->expires_at
                : new DateTimeImmutable($keyRecord->expires_at);
        }

        $capabilities = $keyConfig['capabilities'] ?? $this->parseScopes($keyRecord->scopes ?? null);
        $ipAllowlist = $keyConfig['ip_allowlist'] ?? $appConfig['ip_allowlist'] ?? [];

        return new ClientInfo(
            appCode: $appRecord->app_code,
            name: $appRecord->app_name ?? $appRecord->app_code,
            keyHash: $keyRecord->key_hash,
            channel: $appConfig['channel'] ?? 'partner',
            tenantId: $appConfig['tenant_id'] ?? null,
            capabilities: $capabilities,
            ipAllowlist: $ipAllowlist,
            isActive: (bool) $appRecord->is_active,
            isRevoked: $keyRecord->revoked_at !== null,
            expiresAt: $expiresAt,
            metadata: [
                ...$appMetadata,
                'rate_limit_tier' => $keyConfig['rate_limit_tier'] ?? $appConfig['rate_limit_tier'] ?? 'default',
                'webhook_url' => $keyConfig['webhook_url'] ?? $appConfig['webhook_url'] ?? null,
                'last_used_at' => $keyRecord->last_used_at ?? null,
                'last_used_ip' => $keyRecord->last_used_ip ?? null,
                'last_user_agent' => $keyRecord->last_user_agent ?? null,
                'created_at' => $appRecord->created_at ?? null,
            ],
            id: (string) ($appRecord->id ?? ''),
            keyPrefix: $keyRecord->key_prefix ?? null,
        );
    }

    /**
     * Create a client using the separate apps/keys tables.
     *
     * @param array<string, mixed> $data
     */
    private function createUsingSeparateTables(array $data): ClientInfo
    {
        $keyData = $this->generateKey();
        $now = now();

        $appCode = $data['app_code'] ?? Str::slug($data['name']) . '_' . Str::random(8);
        $appConfig = [
            'channel' => $data['channel'] ?? 'partner',
            'tenant_id' => $data['tenant_id'] ?? null,
            'rate_limit_tier' => $data['rate_limit_tier'] ?? 'default',
            'webhook_url' => $data['webhook_url'] ?? null,
            'ip_allowlist' => $data['ip_allowlist'] ?? [],
        ];

        $appRecord = [
            'app_code' => $appCode,
            'app_name' => $data['name'],
            'description' => $data['description'] ?? null,
            'owner_email' => $data['owner_email'] ?? null,
            'is_active' => $data['is_active'] ?? true,
            'config' => json_encode($appConfig),
            'metadata' => isset($data['metadata']) ? json_encode($data['metadata']) : null,
            'created_at' => $now,
            'updated_at' => $now,
        ];

        $appId = $this->appQuery()->insertGetId($appRecord);

        $capabilities = $data['capabilities'] ?? ['partner:*'];

        $keyRecord = [
            'app_id' => $appId,
            'label' => $data['key_label'] ?? 'default',
            'key_prefix' => $keyData['prefix'],
            'key_hash' => $keyData['hash'],
            'key_ciphertext' => $data['key_ciphertext'] ?? null,
            'phrase' => $data['phrase'] ?? null,
            'scopes' => $this->serializeScopes($capabilities),
            'config' => json_encode([
                'capabilities' => $capabilities,
                'rate_limit_tier' => $data['rate_limit_tier'] ?? 'default',
                'webhook_url' => $data['webhook_url'] ?? null,
                'ip_allowlist' => $data['ip_allowlist'] ?? [],
            ]),
            'expires_at' => $data['expires_at'] ?? null,
            'revoked_at' => null,
            'created_at' => $now,
            'updated_at' => $now,
        ];

        $keyId = $this->appKeyQuery()->insertGetId($keyRecord);

        $clientInfo = $this->toClientInfo(
            (object) [...$appRecord, 'id' => $appId],
            (object) [...$keyRecord, 'id' => $keyId]
        );

        return new ClientInfo(
            appCode: $clientInfo->appCode,
            name: $clientInfo->name,
            keyHash: $clientInfo->keyHash,
            channel: $clientInfo->channel,
            tenantId: $clientInfo->tenantId,
            capabilities: $clientInfo->capabilities,
            ipAllowlist: $clientInfo->ipAllowlist,
            isActive: $clientInfo->isActive,
            isRevoked: $clientInfo->isRevoked,
            expiresAt: $clientInfo->expiresAt,
            metadata: [
                ...$clientInfo->metadata,
                'generated_key' => $keyData['key'],
            ],
            id: $clientInfo->id,
            keyPrefix: $clientInfo->keyPrefix,
        );
    }

    /**
     * Revoke a client and all keys in the separate tables schema.
     */
    private function revokeUsingSeparateTables(string $appCode): bool
    {
        $appRecord = $this->appQuery()
            ->where('app_code', $appCode)
            ->whereNull('deleted_at')
            ->first();

        if ($appRecord === null) {
            return false;
        }

        $this->appQuery()
            ->where('id', $appRecord->id)
            ->update([
                'is_active' => false,
                'updated_at' => now(),
            ]);

        $affected = $this->appKeyQuery()
            ->where('app_id', $appRecord->id)
            ->whereNull('revoked_at')
            ->update([
                'revoked_at' => now(),
                'updated_at' => now(),
            ]);

        return $affected > 0;
    }

    /**
     * List all clients using separate tables.
     *
     * @param array<string, mixed> $filters
     * @return iterable<ClientInfo>
     */
    private function allUsingSeparateTables(array $filters = []): iterable
    {
        $query = $this->appQuery()->whereNull('deleted_at');

        if (!($filters['include_inactive'] ?? false)) {
            $query->where('is_active', true);
        }

        $query->orderBy('created_at', 'desc');

        foreach ($query->cursor() as $appRecord) {
            $keyQuery = $this->appKeyQuery()
                ->where('app_id', $appRecord->id);

            if (!($filters['include_revoked'] ?? false)) {
                $keyQuery->whereNull('revoked_at');
            }

            $keyRecord = $keyQuery->orderBy('created_at', 'desc')->first();

            if ($keyRecord === null) {
                continue;
            }

            $client = $this->toClientInfo($appRecord, $keyRecord);

            if (isset($filters['channel']) && $client->channel !== $filters['channel']) {
                continue;
            }

            if (isset($filters['tenant']) && $client->tenantId !== $filters['tenant']) {
                continue;
            }

            yield $client;
        }
    }

    /**
     * Instantiate an Eloquent model from a class name.
     *
     * @throws RuntimeException
     */
    private function instantiateModel(string $modelClass): Model
    {
        if (!class_exists($modelClass)) {
            throw new RuntimeException("Model class '{$modelClass}' does not exist.");
        }

        $model = new $modelClass();

        if (!$model instanceof Model) {
            throw new RuntimeException("Model class '{$modelClass}' must extend " . Model::class);
        }

        return $model;
    }

    /**
     * Parse scopes from the api_app_keys.scopes field.
     *
     * @return array<string>
     */
    private function parseScopes(array|string|null $scopes): array
    {
        if (is_array($scopes)) {
            return $scopes;
        }

        if ($scopes === null) {
            return [];
        }

        if (is_string($scopes)) {
            $decoded = json_decode($scopes, true);
            if (is_array($decoded)) {
                return $decoded;
            }

            return array_values(array_filter(
                preg_split('/[\s,]+/', $scopes) ?: [],
                static fn(string $value): bool => $value !== ''
            ));
        }

        return [];
    }

    /**
     * Serialize scopes for storage in api_app_keys.scopes.
     *
     * @param array<string> $scopes
     */
    private function serializeScopes(array $scopes): string
    {
        return implode(' ', $scopes);
    }

    /**
     * Hash an API key.
     */
    private function hashKey(string $key): string
    {
        return match ($this->hashAlgorithm) {
            'argon2id' => password_hash($key, PASSWORD_ARGON2ID, [
                'memory_cost' => 65536,
                'time_cost' => 4,
                'threads' => 3,
            ]),
            'bcrypt' => Hash::make($key),
            default => Hash::make($key),
        };
    }
}
