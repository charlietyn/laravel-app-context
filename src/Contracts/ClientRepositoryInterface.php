<?php

declare(strict_types=1);

namespace Ronu\AppContext\Contracts;

use Ronu\AppContext\Support\ClientInfo;

/**
 * Interface for API client storage/retrieval.
 *
 * This interface decouples the library from any specific storage backend,
 * allowing users to implement their own client storage (database, config,
 * external API, Redis, etc.).
 *
 * @package Ronu\AppContext\Contracts
 */
interface ClientRepositoryInterface
{
    /**
     * Find a client by its public identifier (app_code).
     *
     * @param string $appCode The unique client identifier
     * @param string|null $keyPrefix Optional key prefix for multi-key storage
     * @return ClientInfo|null Client data or null if not found/inactive
     */
    public function findByAppCode(string $appCode, ?string $keyPrefix = null): ?ClientInfo;

    /**
     * Verify a key against stored hash.
     *
     * @param string $key The plain API key to verify
     * @param string $storedHash The stored hash to compare against
     * @return bool True if key matches hash
     */
    public function verifyKeyHash(string $key, string $storedHash): bool;

    /**
     * Track usage of a client.
     *
     * This method should be non-blocking and can be a no-op for
     * implementations that don't track usage (like config-based).
     *
     * @param string $appCode The client identifier
     * @param string $ip The IP address of the request
     * @param string|null $keyPrefix Optional key prefix for multi-key storage
     * @param string|null $userAgent Optional user agent for audit trails
     */
    public function trackUsage(
        string $appCode,
        string $ip,
        ?string $keyPrefix = null,
        ?string $userAgent = null
    ): void;

    /**
     * Generate a new API key with hash.
     *
     * @return array{key: string, hash: string, prefix: string}
     */
    public function generateKey(): array;

    /**
     * Create a new client (optional, can throw NotImplementedException).
     *
     * @param array<string, mixed> $data Client data
     * @return ClientInfo The created client
     *
     * @throws \RuntimeException If creation is not supported
     */
    public function create(array $data): ClientInfo;

    /**
     * Revoke a client (optional, can throw NotImplementedException).
     *
     * @param string $appCode The client identifier
     * @return bool True if revoked successfully
     *
     * @throws \RuntimeException If revocation is not supported
     */
    public function revoke(string $appCode): bool;

    /**
     * Get all clients (optional, for listing commands).
     *
     * @param array<string, mixed> $filters Optional filters (channel, tenant, etc.)
     * @return iterable<ClientInfo>
     *
     * @throws \RuntimeException If listing is not supported
     */
    public function all(array $filters = []): iterable;
}
