<?php

declare(strict_types=1);

namespace Ronu\AppContext\Auth\Verifiers;

use Ronu\AppContext\Contracts\ClientRepositoryInterface;
use Ronu\AppContext\Contracts\VerifierInterface;
use Ronu\AppContext\Exceptions\AuthenticationException;
use Ronu\AppContext\Support\ClientInfo;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

/**
 * API Key Verifier for B2B/Partner authentication.
 *
 * This verifier is decoupled from any specific storage backend through
 * the ClientRepositoryInterface. It can work with database-stored clients,
 * config-based clients, or any custom implementation.
 *
 * Security Features:
 * - Argon2id hashing (recommended) or Bcrypt
 * - Expiration validation
 * - Revocation check
 * - IP allowlist support (IPv4/IPv6 with CIDR)
 * - Async usage tracking
 *
 * @package Ronu\AppContext\Auth\Verifiers
 */
final class ApiKeyVerifier implements VerifierInterface
{
    /**
     * @var string Header name for client ID
     */
    private readonly string $clientIdHeader;

    /**
     * @var string Header name for API key
     */
    private readonly string $apiKeyHeader;

    /**
     * @var bool Whether to enforce IP allowlist even when empty
     */
    private readonly bool $enforceIpAllowlist;

    /**
     * @param ClientRepositoryInterface $clientRepository The client storage backend
     * @param array<string, mixed> $config Configuration array
     */
    public function __construct(
        private readonly ClientRepositoryInterface $clientRepository,
        array $config,
    ) {
        $apiKeyConfig = $config['api_key'] ?? $config;
        $securityConfig = $config['security'] ?? [];

        $this->clientIdHeader = $apiKeyConfig['headers']['client_id'] ?? 'X-Client-Id';
        $this->apiKeyHeader = $apiKeyConfig['headers']['api_key'] ?? 'X-Api-Key';
        $this->enforceIpAllowlist = $securityConfig['enforce_ip_allowlist'] ?? false;
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

        // Find client via repository
        $client = $this->clientRepository->findByAppCode($clientId);
        if ($client === null) {
            Log::warning('API key verification failed: client not found', [
                'client_id' => $clientId,
                'ip' => $request->ip(),
            ]);
            throw AuthenticationException::clientNotFound();
        }

        // Verify key hash via repository
        if (!$this->clientRepository->verifyKeyHash($apiKey, $client->keyHash)) {
            Log::warning('API key verification failed: invalid key', [
                'client_id' => $clientId,
                'ip' => $request->ip(),
            ]);
            throw AuthenticationException::invalidApiKey();
        }

        // Check expiration
        if ($client->isExpired()) {
            Log::warning('API key verification failed: expired', [
                'client_id' => $clientId,
                'expires_at' => $client->expiresAt?->format('Y-m-d H:i:s'),
            ]);
            throw AuthenticationException::expiredApiKey();
        }

        // Check revocation
        if ($client->isRevoked) {
            Log::warning('API key verification failed: revoked', [
                'client_id' => $clientId,
            ]);
            throw AuthenticationException::revokedApiKey();
        }

        // Check IP allowlist
        if (!$this->isIpAllowed($request->ip(), $client)) {
            Log::warning('API key verification failed: IP not allowed', [
                'client_id' => $clientId,
                'ip' => $request->ip(),
                'allowlist' => $client->ipAllowlist,
            ]);
            throw AuthenticationException::ipNotAllowed($request->ip());
        }

        // Track usage via repository
        $this->clientRepository->trackUsage($client->appCode, $request->ip());

        return [
            'client_id' => $client->appCode,
            'client_name' => $client->name,
            'channel' => $client->channel,
            'tenant_id' => $client->tenantId,
            'capabilities' => $client->capabilities,
            'metadata' => [
                'client_uuid' => $client->id,
                'rate_limit_tier' => $client->getMeta('rate_limit_tier', 'default'),
                'webhook_url' => $client->getMeta('webhook_url'),
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
        return $this->clientRepository->generateKey();
    }

    /**
     * Get the underlying client repository.
     *
     * Useful for commands that need direct access to create/revoke/list operations.
     */
    public function getRepository(): ClientRepositoryInterface
    {
        return $this->clientRepository;
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
     * Check if IP is allowed.
     */
    private function isIpAllowed(string $ip, ClientInfo $client): bool
    {
        // If no allowlist, allow all unless enforcement is enabled
        if (empty($client->ipAllowlist)) {
            return !$this->enforceIpAllowlist;
        }

        foreach ($client->ipAllowlist as $allowed) {
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

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
            || filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
        ) {
            return $this->ipInCidrV6($ip, $subnet, (int) $bits);
        }

        return $this->ipInCidrV4($ip, $subnet, (int) $bits);
    }

    /**
     * Check if IPv4 is in CIDR range.
     */
    private function ipInCidrV4(string $ip, string $subnet, int $bits): bool
    {
        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        $mask = -1 << (32 - $bits);
        $subnetLong &= $mask;

        return ($ipLong & $mask) === $subnetLong;
    }

    /**
     * Check if IPv6 is in CIDR range.
     */
    private function ipInCidrV6(string $ip, string $subnet, int $bits): bool
    {
        $ipPacked = inet_pton($ip);
        $subnetPacked = inet_pton($subnet);

        if ($ipPacked === false || $subnetPacked === false) {
            return false;
        }

        $bytes = intdiv($bits, 8);
        $remainderBits = $bits % 8;

        if ($bytes > 0 && substr($ipPacked, 0, $bytes) !== substr($subnetPacked, 0, $bytes)) {
            return false;
        }

        if ($remainderBits === 0) {
            return true;
        }

        $mask = ~(0xff >> $remainderBits) & 0xff;
        $ipByte = ord($ipPacked[$bytes]);
        $subnetByte = ord($subnetPacked[$bytes]);

        return ($ipByte & $mask) === ($subnetByte & $mask);
    }
}
