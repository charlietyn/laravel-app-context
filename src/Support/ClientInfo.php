<?php

declare(strict_types=1);

namespace Ronu\AppContext\Support;

use DateTimeImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use JsonSerializable;

/**
 * Immutable value object representing API client data.
 *
 * This class decouples the library from specific ORM models (like Eloquent),
 * allowing it to work with any storage backend.
 *
 * @package Ronu\AppContext\Support
 *
 * @implements Arrayable<string, mixed>
 */
final class ClientInfo implements Arrayable, Jsonable, JsonSerializable
{
    /**
     * @param string $appCode Unique client identifier (used in X-Client-Id header)
     * @param string $name Human-readable client name
     * @param string $keyHash Hashed API key (Argon2id, Bcrypt, etc.)
     * @param string $channel Authorized channel (partner, admin, etc.)
     * @param string|null $tenantId Tenant restriction (null = all tenants)
     * @param array<string> $capabilities List of capabilities/permissions
     * @param array<string> $ipAllowlist IP allowlist (supports CIDR notation)
     * @param bool $isActive Whether client is active
     * @param bool $isRevoked Whether client has been revoked
     * @param DateTimeInterface|null $expiresAt Expiration date (null = never)
     * @param array<string, mixed> $metadata Additional metadata (rate_limit_tier, webhook_url, etc.)
     * @param string|null $id Internal ID (UUID, int, etc.) for tracking
     * @param string|null $keyPrefix First chars of key for identification
     */
    public function __construct(
        public readonly string $appCode,
        public readonly string $name,
        public readonly string $keyHash,
        public readonly string $channel,
        public readonly ?string $tenantId,
        public readonly array $capabilities,
        public readonly array $ipAllowlist,
        public readonly bool $isActive,
        public readonly bool $isRevoked,
        public readonly ?DateTimeInterface $expiresAt,
        public readonly array $metadata = [],
        public readonly ?string $id = null,
        public readonly ?string $keyPrefix = null,
    ) {}

    /**
     * Check if the client key is expired.
     */
    public function isExpired(): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }

        return $this->expiresAt < new DateTimeImmutable();
    }

    /**
     * Check if the client is valid (active, not revoked, not expired).
     */
    public function isValid(): bool
    {
        return $this->isActive && !$this->isRevoked && !$this->isExpired();
    }

    /**
     * Check if the client has a specific capability.
     *
     * Supports wildcard matching (e.g., "partner:*" matches "partner:orders:read").
     */
    public function hasCapability(string $capability): bool
    {
        foreach ($this->capabilities as $cap) {
            if ($cap === $capability) {
                return true;
            }

            // Wildcard matching
            if (str_ends_with($cap, ':*')) {
                $prefix = substr($cap, 0, -1);
                if (str_starts_with($capability, $prefix)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Get a metadata value.
     *
     * @param string $key Metadata key
     * @param mixed $default Default value if key doesn't exist
     * @return mixed
     */
    public function getMeta(string $key, mixed $default = null): mixed
    {
        return $this->metadata[$key] ?? $default;
    }

    /**
     * Create from array (for config-based or serialized clients).
     *
     * @param array<string, mixed> $data Client data
     */
    public static function fromArray(array $data): self
    {
        $expiresAt = null;
        if (isset($data['expires_at']) && $data['expires_at'] !== null) {
            $expiresAt = $data['expires_at'] instanceof DateTimeInterface
                ? $data['expires_at']
                : new DateTimeImmutable($data['expires_at']);
        }

        return new self(
            appCode: $data['app_code'],
            name: $data['name'] ?? $data['app_code'],
            keyHash: $data['key_hash'],
            channel: $data['channel'] ?? 'partner',
            tenantId: $data['tenant_id'] ?? null,
            capabilities: $data['capabilities'] ?? [],
            ipAllowlist: $data['ip_allowlist'] ?? [],
            isActive: $data['is_active'] ?? true,
            isRevoked: $data['is_revoked'] ?? false,
            expiresAt: $expiresAt,
            metadata: $data['metadata'] ?? [],
            id: $data['id'] ?? null,
            keyPrefix: $data['key_prefix'] ?? null,
        );
    }

    /**
     * Create from an Eloquent model (for backwards compatibility).
     *
     * @param object $model Model with expected properties
     */
    public static function fromModel(object $model): self
    {
        $config = is_array($model->config) ? $model->config : json_decode($model->config ?? '{}', true);
        $ipAllowlist = is_array($model->ip_allowlist) ? $model->ip_allowlist : json_decode($model->ip_allowlist ?? '[]', true);

        return new self(
            appCode: $model->app_code,
            name: $model->name,
            keyHash: $model->key_hash,
            channel: $model->channel,
            tenantId: $model->tenant_id,
            capabilities: $config['capabilities'] ?? [],
            ipAllowlist: $ipAllowlist,
            isActive: (bool) $model->is_active,
            isRevoked: (bool) $model->is_revoked,
            expiresAt: $model->expires_at,
            metadata: [
                'rate_limit_tier' => $config['rate_limit_tier'] ?? 'default',
                'webhook_url' => $config['webhook_url'] ?? null,
            ],
            id: $model->id ?? null,
            keyPrefix: $model->key_prefix ?? null,
        );
    }

    /**
     * Convert to array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'app_code' => $this->appCode,
            'name' => $this->name,
            'key_hash' => $this->keyHash,
            'key_prefix' => $this->keyPrefix,
            'channel' => $this->channel,
            'tenant_id' => $this->tenantId,
            'capabilities' => $this->capabilities,
            'ip_allowlist' => $this->ipAllowlist,
            'is_active' => $this->isActive,
            'is_revoked' => $this->isRevoked,
            'expires_at' => $this->expiresAt?->format('Y-m-d H:i:s'),
            'metadata' => $this->metadata,
        ];
    }

    /**
     * Convert to JSON.
     *
     * @param int $options JSON encoding options
     * @return string
     */
    public function toJson($options = 0): string
    {
        return json_encode($this->jsonSerialize(), $options | JSON_THROW_ON_ERROR);
    }

    /**
     * Data to serialize to JSON.
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
