<?php

declare(strict_types=1);

namespace Ronu\AppContext\Repositories;

use Ronu\AppContext\Contracts\ClientRepositoryInterface;
use Ronu\AppContext\Support\ClientInfo;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * Config-based client repository.
 *
 * This implementation allows defining API clients directly in configuration,
 * eliminating the need for database migrations. Ideal for:
 * - Simple setups with few partners
 * - Development/testing environments
 * - Stateless deployments
 * - Configuration-as-code approaches
 *
 * @package Ronu\AppContext\Repositories
 */
final class ConfigClientRepository implements ClientRepositoryInterface
{
    /**
     * @var array<string, array<string, mixed>> Configured clients
     */
    private readonly array $clients;

    /**
     * @var string Hash algorithm for key generation
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
     * @param array<string, mixed> $config Repository configuration
     */
    public function __construct(array $config)
    {
        $this->clients = $config['clients'] ?? [];
        $this->hashAlgorithm = $config['hash_algorithm'] ?? 'bcrypt';
        $this->prefixLength = $config['prefix_length'] ?? 10;
        $this->keyLength = $config['key_length'] ?? 32;
    }

    /**
     * {@inheritdoc}
     */
    public function findByAppCode(string $appCode, ?string $keyPrefix = null): ?ClientInfo
    {
        if (!isset($this->clients[$appCode])) {
            return null;
        }

        $clientData = $this->clients[$appCode];

        // Check if active
        if (!($clientData['is_active'] ?? true)) {
            return null;
        }

        return ClientInfo::fromArray([
            'app_code' => $appCode,
            ...$clientData,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function verifyKeyHash(string $key, string $storedHash): bool
    {
        return match ($this->hashAlgorithm) {
            'argon2id' => password_verify($key, $storedHash),
            'bcrypt' => Hash::check($key, $storedHash),
            'plain' => hash_equals($storedHash, $key), // Only for development
            default => Hash::check($key, $storedHash),
        };
    }

    /**
     * {@inheritdoc}
     *
     * No-op for config-based repository.
     */
    public function trackUsage(
        string $appCode,
        string $ip,
        ?string $keyPrefix = null,
        ?string $userAgent = null
    ): void
    {
        // Config-based repository doesn't track usage
        // Override in custom implementation if needed
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
     *
     * @throws RuntimeException Config-based repository doesn't support creation
     */
    public function create(array $data): ClientInfo
    {
        throw new RuntimeException(
            'ConfigClientRepository does not support creating clients. ' .
            'Add clients manually to the configuration file or use EloquentClientRepository.'
        );
    }

    /**
     * {@inheritdoc}
     *
     * @throws RuntimeException Config-based repository doesn't support revocation
     */
    public function revoke(string $appCode): bool
    {
        throw new RuntimeException(
            'ConfigClientRepository does not support revoking clients. ' .
            'Set is_revoked: true in configuration or use EloquentClientRepository.'
        );
    }

    /**
     * {@inheritdoc}
     */
    public function all(array $filters = []): iterable
    {
        foreach ($this->clients as $appCode => $clientData) {
            $client = ClientInfo::fromArray([
                'app_code' => $appCode,
                ...$clientData,
            ]);

            // Apply filters
            if (isset($filters['channel']) && $client->channel !== $filters['channel']) {
                continue;
            }

            if (isset($filters['tenant']) && $client->tenantId !== $filters['tenant']) {
                continue;
            }

            if (!($filters['include_revoked'] ?? false) && $client->isRevoked) {
                continue;
            }

            if (!($filters['include_inactive'] ?? false) && !$client->isActive) {
                continue;
            }

            yield $client;
        }
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
            'plain' => $key, // Only for development
            default => Hash::make($key),
        };
    }

    /**
     * Helper method to generate a hash for configuration.
     *
     * Usage in tinker:
     *   app(ConfigClientRepository::class)->hashForConfig('my-secret-key')
     *
     * @param string $key The plain key to hash
     * @return string Hash suitable for configuration file
     */
    public function hashForConfig(string $key): string
    {
        return $this->hashKey($key);
    }
}
