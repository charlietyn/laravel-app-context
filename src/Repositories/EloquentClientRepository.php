<?php

declare(strict_types=1);

namespace Ronu\AppContext\Repositories;

use Ronu\AppContext\Contracts\ClientRepositoryInterface;
use Ronu\AppContext\Support\ClientInfo;
use DateTimeImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * Eloquent/Database-based client repository.
 *
 * This implementation uses direct database queries (not a specific model),
 * allowing users to use any table structure that matches the expected schema.
 *
 * Required columns:
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
 * Optional columns for tracking:
 * - last_used_at (timestamp)
 * - last_used_ip (string)
 * - usage_count (integer)
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
        $this->table = $config['table'] ?? 'api_clients';
        $this->connection = $config['connection'] ?? null;
        $this->hashAlgorithm = $config['hash_algorithm'] ?? 'argon2id';
        $this->prefixLength = $config['prefix_length'] ?? 10;
        $this->keyLength = $config['key_length'] ?? 32;
        $this->asyncTracking = $config['async_tracking'] ?? true;
    }

    /**
     * {@inheritdoc}
     */
    public function findByAppCode(string $appCode): ?ClientInfo
    {
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
    public function trackUsage(string $appCode, string $ip): void
    {
        $updateFn = function () use ($appCode, $ip) {
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
     * Convert database record to ClientInfo.
     */
    private function toClientInfo(object $record): ClientInfo
    {
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
