<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Auth\Verifiers;

use Charlietyn\AppContext\Contracts\VerifierInterface;
use Charlietyn\AppContext\Exceptions\AuthenticationException;
use Charlietyn\AppContext\Models\ApiClient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

/**
 * API Key Verifier for B2B/Partner authentication.
 *
 * Security Features:
 * - Argon2id hashing (recommended) or Bcrypt
 * - Expiration validation
 * - Revocation check
 * - IP allowlist support (CIDR)
 * - Async usage tracking
 */
final class ApiKeyVerifier implements VerifierInterface
{
    private readonly string $clientIdHeader;
    private readonly string $apiKeyHeader;
    private readonly string $hashAlgorithm;

    public function __construct(array $config)
    {
        $this->clientIdHeader = $config['headers']['client_id'] ?? 'X-Client-Id';
        $this->apiKeyHeader = $config['headers']['api_key'] ?? 'X-Api-Key';
        $this->hashAlgorithm = $config['hash_algorithm'] ?? 'argon2id';
    }

    /**
     * Verify API key from request.
     *
     * @return array{
     *     client_id: string,
     *     client_name: string,
     *     channel: string,
     *     tenant_id: string|null,
     *     capabilities: array,
     *     metadata: array
     * }
     *
     * @throws AuthenticationException
     */
    public function verify(Request $request): array
    {
        $clientId = $this->extractClientId($request);
        $apiKey = $this->extractApiKey($request);

        if ($clientId === null || $apiKey === null) {
            throw AuthenticationException::missingApiKey();
        }

        // Find client
        $client = $this->findClient($clientId);
        if ($client === null) {
            Log::warning('API key verification failed: client not found', [
                'client_id' => $clientId,
                'ip' => $request->ip(),
            ]);
            throw AuthenticationException::clientNotFound();
        }

        // Verify key hash
        if (! $this->verifyKeyHash($apiKey, $client->key_hash)) {
            Log::warning('API key verification failed: invalid key', [
                'client_id' => $clientId,
                'ip' => $request->ip(),
            ]);
            throw AuthenticationException::invalidApiKey();
        }

        // Check expiration
        if ($client->expires_at !== null && $client->expires_at->isPast()) {
            Log::warning('API key verification failed: expired', [
                'client_id' => $clientId,
                'expires_at' => $client->expires_at,
            ]);
            throw AuthenticationException::expiredApiKey();
        }

        // Check revocation
        if ($client->is_revoked) {
            Log::warning('API key verification failed: revoked', [
                'client_id' => $clientId,
            ]);
            throw AuthenticationException::revokedApiKey();
        }

        // Check IP allowlist
        if (! $this->isIpAllowed($request->ip(), $client)) {
            Log::warning('API key verification failed: IP not allowed', [
                'client_id' => $clientId,
                'ip' => $request->ip(),
                'allowlist' => $client->ip_allowlist,
            ]);
            throw AuthenticationException::ipNotAllowed($request->ip());
        }

        // Track usage asynchronously
        $this->trackUsage($client, $request);

        return [
            'client_id' => $client->app_code,
            'client_name' => $client->name,
            'channel' => $client->channel,
            'tenant_id' => $client->tenant_id,
            'capabilities' => $client->config['capabilities'] ?? [],
            'metadata' => [
                'client_uuid' => $client->id,
                'rate_limit_tier' => $client->config['rate_limit_tier'] ?? 'default',
                'webhook_url' => $client->config['webhook_url'] ?? null,
            ],
        ];
    }

    /**
     * Check if verifier can handle the request.
     */
    public function canHandle(Request $request): bool
    {
        return $this->extractClientId($request) !== null
            && $this->extractApiKey($request) !== null;
    }

    /**
     * Get the credential type.
     */
    public function getCredentialType(): string
    {
        return 'api_key';
    }

    /**
     * Generate a new API key.
     *
     * @return array{key: string, hash: string, prefix: string}
     */
    public function generateKey(): array
    {
        $prefix = Str::random(config('app-context.api_key.prefix_length', 10));
        $secret = Str::random(config('app-context.api_key.key_length', 32));
        $key = "{$prefix}.{$secret}";

        return [
            'key' => $key,
            'hash' => $this->hashKey($key),
            'prefix' => $prefix,
        ];
    }

    /**
     * Hash an API key.
     */
    public function hashKey(string $key): string
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

    /**
     * Extract client ID from request.
     */
    private function extractClientId(Request $request): ?string
    {
        return $request->header($this->clientIdHeader);
    }

    /**
     * Extract API key from request.
     */
    private function extractApiKey(Request $request): ?string
    {
        return $request->header($this->apiKeyHeader);
    }

    /**
     * Find API client by app code.
     */
    private function findClient(string $clientId): ?ApiClient
    {
        return ApiClient::where('app_code', $clientId)
            ->where('is_active', true)
            ->first();
    }

    /**
     * Verify key hash.
     */
    private function verifyKeyHash(string $key, string $hash): bool
    {
        return match ($this->hashAlgorithm) {
            'argon2id' => password_verify($key, $hash),
            'bcrypt' => Hash::check($key, $hash),
            default => Hash::check($key, $hash),
        };
    }

    /**
     * Check if IP is allowed.
     */
    private function isIpAllowed(string $ip, ApiClient $client): bool
    {
        // If no allowlist, allow all
        if (empty($client->ip_allowlist)) {
            return true;
        }

        foreach ($client->ip_allowlist as $allowed) {
            // Check exact match
            if ($ip === $allowed) {
                return true;
            }

            // Check CIDR notation
            if (str_contains($allowed, '/') && $this->ipInCidr($ip, $allowed)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if IP is in CIDR range.
     */
    private function ipInCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr);

        $ip = ip2long($ip);
        $subnet = ip2long($subnet);
        $mask = -1 << (32 - (int) $bits);

        $subnet &= $mask;

        return ($ip & $mask) === $subnet;
    }

    /**
     * Track API key usage asynchronously.
     */
    private function trackUsage(ApiClient $client, Request $request): void
    {
        // Use a queue job or async update to not block the request
        dispatch(function () use ($client, $request) {
            $client->update([
                'last_used_at' => now(),
                'last_used_ip' => $request->ip(),
                'usage_count' => $client->usage_count + 1,
            ]);
        })->afterResponse();
    }
}
