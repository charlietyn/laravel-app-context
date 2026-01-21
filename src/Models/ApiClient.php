<?php

declare(strict_types=1);

namespace Ronu\AppContext\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * API Client model for B2B/Partner authentication.
 *
 * @property string $id UUID
 * @property string $name Client name
 * @property string $app_code Unique client identifier (used in X-Client-Id header)
 * @property string $key_hash Hashed API key (Argon2id or Bcrypt)
 * @property string|null $key_prefix First characters of the key for identification
 * @property string $channel Authorized channel (partner, admin, etc.)
 * @property string|null $tenant_id Tenant restriction
 * @property array $config Configuration (capabilities, rate_limit_tier, webhook_url)
 * @property array|null $ip_allowlist IP allowlist (supports CIDR)
 * @property bool $is_active Whether client is active
 * @property bool $is_revoked Whether client is revoked
 * @property \Carbon\Carbon|null $expires_at Key expiration date
 * @property \Carbon\Carbon|null $last_used_at Last usage timestamp
 * @property string|null $last_used_ip Last usage IP
 * @property int $usage_count Total usage count
 * @property \Carbon\Carbon $created_at
 * @property \Carbon\Carbon $updated_at
 * @property \Carbon\Carbon|null $deleted_at
 */
class ApiClient extends Model
{
    use HasUuids;
    use SoftDeletes;

    protected $table = 'api_clients';

    protected $fillable = [
        'name',
        'app_code',
        'key_hash',
        'key_prefix',
        'channel',
        'tenant_id',
        'config',
        'ip_allowlist',
        'is_active',
        'is_revoked',
        'expires_at',
        'last_used_at',
        'last_used_ip',
        'usage_count',
    ];

    protected $casts = [
        'config' => 'array',
        'ip_allowlist' => 'array',
        'is_active' => 'boolean',
        'is_revoked' => 'boolean',
        'expires_at' => 'datetime',
        'last_used_at' => 'datetime',
        'usage_count' => 'integer',
    ];

    protected $hidden = [
        'key_hash',
    ];

    /**
     * Get capabilities from config.
     */
    public function getCapabilitiesAttribute(): array
    {
        return $this->config['capabilities'] ?? [];
    }

    /**
     * Check if the client has a specific capability.
     */
    public function hasCapability(string $capability): bool
    {
        $capabilities = $this->capabilities;

        foreach ($capabilities as $cap) {
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
     * Check if the key is expired.
     */
    public function isExpired(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }

    /**
     * Check if the key is valid (active, not revoked, not expired).
     */
    public function isValid(): bool
    {
        return $this->is_active && ! $this->is_revoked && ! $this->isExpired();
    }

    /**
     * Revoke the client.
     */
    public function revoke(): bool
    {
        return $this->update(['is_revoked' => true]);
    }

    /**
     * Activate the client.
     */
    public function activate(): bool
    {
        return $this->update(['is_active' => true, 'is_revoked' => false]);
    }

    /**
     * Deactivate the client.
     */
    public function deactivate(): bool
    {
        return $this->update(['is_active' => false]);
    }

    /**
     * Scope: Active clients only.
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true)->where('is_revoked', false);
    }

    /**
     * Scope: By channel.
     */
    public function scopeForChannel($query, string $channel)
    {
        return $query->where('channel', $channel);
    }

    /**
     * Scope: By tenant.
     */
    public function scopeForTenant($query, string $tenantId)
    {
        return $query->where('tenant_id', $tenantId);
    }
}
