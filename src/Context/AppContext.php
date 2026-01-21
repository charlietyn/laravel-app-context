<?php

declare(strict_types=1);

namespace Ronu\AppContext\Context;

use Ronu\AppContext\Exceptions\AuthorizationException;
use Ronu\AppContext\Support\ScopeChecker;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use JsonSerializable;
use Stringable;

/**
 * Immutable Value Object that encapsulates the complete application context
 * for a single request execution.
 *
 * @property-read string|null $appId Channel identifier (mobile, admin, site, partner)
 * @property-read string|null $authMode Authentication mode (jwt, api_key, anonymous)
 * @property-read int|string|null $userId Authenticated user ID (for JWT)
 * @property-read string|null $clientId API client identifier (for API Key)
 * @property-read string|null $tenantId Tenant identifier (multi-tenant)
 * @property-read array $scopes JWT scopes (channel:resource:action)
 * @property-read array $capabilities API Key capabilities
 * @property-read array $metadata Additional context data
 * @property-read string|null $deviceId Device fingerprint (mobile)
 * @property-read string|null $ipAddress Client IP address
 * @property-read string $requestId Unique request identifier
 */
final class AppContext implements Arrayable, Jsonable, JsonSerializable, Stringable
{
    private readonly ScopeChecker $scopeChecker;

    /**
     * Create a new AppContext instance.
     *
     * @param string|null $appId Channel identifier
     * @param string|null $authMode Authentication mode
     * @param int|string|null $userId User ID (JWT auth)
     * @param string|null $clientId Client ID (API Key auth)
     * @param string|null $tenantId Tenant ID
     * @param array $scopes JWT scopes
     * @param array $capabilities API Key capabilities
     * @param array $metadata Additional metadata
     * @param string|null $deviceId Device fingerprint
     * @param string|null $ipAddress Client IP
     * @param string|null $requestId Request ID (auto-generated if null)
     */
    public function __construct(
        private readonly ?string $appId = null,
        private readonly ?string $authMode = null,
        private readonly int|string|null $userId = null,
        private readonly ?string $clientId = null,
        private readonly ?string $tenantId = null,
        private readonly array $scopes = [],
        private readonly array $capabilities = [],
        private readonly array $metadata = [],
        private readonly ?string $deviceId = null,
        private readonly ?string $ipAddress = null,
        private readonly ?string $requestId = null,
    ) {
        $this->scopeChecker = new ScopeChecker();
    }

    // =========================================================================
    // Factory Methods
    // =========================================================================

    /**
     * Create context from channel configuration.
     */
    public static function fromChannel(
        string $appId,
        string $authMode,
        ?string $ipAddress = null,
        ?string $requestId = null,
    ): self {
        return new self(
            appId: $appId,
            authMode: $authMode,
            ipAddress: $ipAddress,
            requestId: $requestId ?? self::generateRequestId(),
        );
    }

    /**
     * Create context from JWT claims.
     */
    public static function fromJwt(
        string $appId,
        array $claims,
        ?string $ipAddress = null,
        ?string $requestId = null,
    ): self {
        return new self(
            appId: $appId,
            authMode: 'jwt',
            userId: $claims['sub'] ?? null,
            tenantId: $claims['tid'] ?? null,
            scopes: $claims['scp'] ?? $claims['scopes'] ?? [],
            metadata: [
                'jwt_id' => $claims['jti'] ?? null,
                'issued_at' => $claims['iat'] ?? null,
                'expires_at' => $claims['exp'] ?? null,
                'audience' => $claims['aud'] ?? null,
            ],
            deviceId: $claims['did'] ?? $claims['device_id'] ?? null,
            ipAddress: $ipAddress,
            requestId: $requestId ?? self::generateRequestId(),
        );
    }

    /**
     * Create context from API Key verification.
     */
    public static function fromApiKey(
        string $appId,
        string $clientId,
        array $capabilities,
        ?string $tenantId = null,
        ?string $ipAddress = null,
        ?string $requestId = null,
        array $metadata = [],
    ): self {
        return new self(
            appId: $appId,
            authMode: 'api_key',
            clientId: $clientId,
            tenantId: $tenantId,
            capabilities: $capabilities,
            metadata: $metadata,
            ipAddress: $ipAddress,
            requestId: $requestId ?? self::generateRequestId(),
        );
    }

    /**
     * Create anonymous context.
     */
    public static function anonymous(
        string $appId,
        ?string $ipAddress = null,
        ?string $requestId = null,
    ): self {
        return new self(
            appId: $appId,
            authMode: 'anonymous',
            scopes: ['public:read', 'catalog:browse'],
            ipAddress: $ipAddress,
            requestId: $requestId ?? self::generateRequestId(),
        );
    }

    // =========================================================================
    // Getters
    // =========================================================================

    public function getAppId(): ?string
    {
        return $this->appId;
    }

    public function getAuthMode(): ?string
    {
        return $this->authMode;
    }

    public function getUserId(): int|string|null
    {
        return $this->userId;
    }

    public function getClientId(): ?string
    {
        return $this->clientId;
    }

    public function getTenantId(): ?string
    {
        return $this->tenantId;
    }

    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function getCapabilities(): array
    {
        return $this->capabilities;
    }

    public function getMetadata(): array
    {
        return $this->metadata;
    }

    public function getMetadataValue(string $key, mixed $default = null): mixed
    {
        return $this->metadata[$key] ?? $default;
    }

    public function getDeviceId(): ?string
    {
        return $this->deviceId;
    }

    public function getIpAddress(): ?string
    {
        return $this->ipAddress;
    }

    public function getRequestId(): string
    {
        return $this->requestId ?? self::generateRequestId();
    }

    // =========================================================================
    // Authorization Methods
    // =========================================================================

    /**
     * Check if the context is authenticated.
     */
    public function isAuthenticated(): bool
    {
        return $this->userId !== null || $this->clientId !== null;
    }

    /**
     * Check if context has a specific scope.
     * Supports wildcards: admin:* matches admin:users:read
     */
    public function hasScope(string $scope): bool
    {
        return $this->scopeChecker->hasScope($this->scopes, $scope);
    }

    /**
     * Check if context has a specific capability.
     * Supports wildcards: partner:* matches partner:orders:create
     */
    public function hasCapability(string $capability): bool
    {
        return $this->scopeChecker->hasScope($this->capabilities, $capability);
    }

    /**
     * Check if context has any of the given scopes.
     */
    public function hasAnyScope(array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if ($this->hasScope($scope)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if context has all of the given scopes.
     */
    public function hasAllScopes(array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if (! $this->hasScope($scope)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if context has any of the given capabilities.
     */
    public function hasAnyCapability(array $capabilities): bool
    {
        foreach ($capabilities as $capability) {
            if ($this->hasCapability($capability)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if context has all of the given capabilities.
     */
    public function hasAllCapabilities(array $capabilities): bool
    {
        foreach ($capabilities as $capability) {
            if (! $this->hasCapability($capability)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Require a scope or capability, throw exception if missing.
     *
     * @throws AuthorizationException
     */
    public function requires(string $scopeOrCapability): void
    {
        if (! $this->hasScope($scopeOrCapability) && ! $this->hasCapability($scopeOrCapability)) {
            throw new AuthorizationException(
                "Missing required permission: {$scopeOrCapability}",
                $scopeOrCapability
            );
        }
    }

    /**
     * Require any of the given scopes or capabilities.
     *
     * @throws AuthorizationException
     */
    public function requiresAny(array $permissions): void
    {
        if (! $this->hasAnyScope($permissions) && ! $this->hasAnyCapability($permissions)) {
            throw new AuthorizationException(
                'Missing required permission. Required one of: ' . implode(', ', $permissions),
                $permissions
            );
        }
    }

    /**
     * Require all of the given scopes or capabilities.
     *
     * @throws AuthorizationException
     */
    public function requiresAll(array $permissions): void
    {
        foreach ($permissions as $permission) {
            $this->requires($permission);
        }
    }

    // =========================================================================
    // Immutable Modifiers (return new instances)
    // =========================================================================

    /**
     * Return a new context with the given user ID.
     */
    public function withUserId(int|string $userId): self
    {
        return new self(
            appId: $this->appId,
            authMode: $this->authMode,
            userId: $userId,
            clientId: $this->clientId,
            tenantId: $this->tenantId,
            scopes: $this->scopes,
            capabilities: $this->capabilities,
            metadata: $this->metadata,
            deviceId: $this->deviceId,
            ipAddress: $this->ipAddress,
            requestId: $this->requestId,
        );
    }

    /**
     * Return a new context with the given client ID.
     */
    public function withClientId(string $clientId): self
    {
        return new self(
            appId: $this->appId,
            authMode: $this->authMode,
            userId: $this->userId,
            clientId: $clientId,
            tenantId: $this->tenantId,
            scopes: $this->scopes,
            capabilities: $this->capabilities,
            metadata: $this->metadata,
            deviceId: $this->deviceId,
            ipAddress: $this->ipAddress,
            requestId: $this->requestId,
        );
    }

    /**
     * Return a new context with the given tenant ID.
     */
    public function withTenantId(string $tenantId): self
    {
        return new self(
            appId: $this->appId,
            authMode: $this->authMode,
            userId: $this->userId,
            clientId: $this->clientId,
            tenantId: $tenantId,
            scopes: $this->scopes,
            capabilities: $this->capabilities,
            metadata: $this->metadata,
            deviceId: $this->deviceId,
            ipAddress: $this->ipAddress,
            requestId: $this->requestId,
        );
    }

    /**
     * Return a new context with the given scopes.
     */
    public function withScopes(array $scopes): self
    {
        return new self(
            appId: $this->appId,
            authMode: $this->authMode,
            userId: $this->userId,
            clientId: $this->clientId,
            tenantId: $this->tenantId,
            scopes: $scopes,
            capabilities: $this->capabilities,
            metadata: $this->metadata,
            deviceId: $this->deviceId,
            ipAddress: $this->ipAddress,
            requestId: $this->requestId,
        );
    }

    /**
     * Return a new context with merged scopes.
     */
    public function addScopes(array $scopes): self
    {
        return $this->withScopes(array_unique([...$this->scopes, ...$scopes]));
    }

    /**
     * Return a new context with the given capabilities.
     */
    public function withCapabilities(array $capabilities): self
    {
        return new self(
            appId: $this->appId,
            authMode: $this->authMode,
            userId: $this->userId,
            clientId: $this->clientId,
            tenantId: $this->tenantId,
            scopes: $this->scopes,
            capabilities: $capabilities,
            metadata: $this->metadata,
            deviceId: $this->deviceId,
            ipAddress: $this->ipAddress,
            requestId: $this->requestId,
        );
    }

    /**
     * Return a new context with the given metadata.
     */
    public function withMetadata(array $metadata): self
    {
        return new self(
            appId: $this->appId,
            authMode: $this->authMode,
            userId: $this->userId,
            clientId: $this->clientId,
            tenantId: $this->tenantId,
            scopes: $this->scopes,
            capabilities: $this->capabilities,
            metadata: $metadata,
            deviceId: $this->deviceId,
            ipAddress: $this->ipAddress,
            requestId: $this->requestId,
        );
    }

    /**
     * Return a new context with merged metadata.
     */
    public function addMetadata(string $key, mixed $value): self
    {
        return $this->withMetadata([...$this->metadata, $key => $value]);
    }

    /**
     * Return a new context with the given device ID.
     */
    public function withDeviceId(string $deviceId): self
    {
        return new self(
            appId: $this->appId,
            authMode: $this->authMode,
            userId: $this->userId,
            clientId: $this->clientId,
            tenantId: $this->tenantId,
            scopes: $this->scopes,
            capabilities: $this->capabilities,
            metadata: $this->metadata,
            deviceId: $deviceId,
            ipAddress: $this->ipAddress,
            requestId: $this->requestId,
        );
    }

    // =========================================================================
    // Utility Methods
    // =========================================================================

    /**
     * Get the rate limit key for this context.
     */
    public function getRateLimitKey(): string
    {
        $parts = [$this->appId ?? 'unknown'];

        if ($this->userId !== null) {
            $parts[] = "user:{$this->userId}";
        } elseif ($this->clientId !== null) {
            $parts[] = "client:{$this->clientId}";
        } else {
            $parts[] = "ip:{$this->ipAddress}";
        }

        if ($this->deviceId !== null) {
            $parts[] = "device:{$this->deviceId}";
        }

        return implode(':', $parts);
    }

    /**
     * Get context data for logging.
     */
    public function toLogContext(): array
    {
        return array_filter([
            'app_id' => $this->appId,
            'auth_mode' => $this->authMode,
            'user_id' => $this->userId,
            'client_id' => $this->clientId,
            'tenant_id' => $this->tenantId,
            'device_id' => $this->deviceId,
            'ip_address' => $this->ipAddress,
            'request_id' => $this->getRequestId(),
        ], fn ($value) => $value !== null);
    }

    /**
     * Generate a unique request ID.
     */
    private static function generateRequestId(): string
    {
        return sprintf(
            '%s-%s',
            date('YmdHis'),
            bin2hex(random_bytes(8))
        );
    }

    // =========================================================================
    // Interface Implementations
    // =========================================================================

    public function toArray(): array
    {
        return [
            'app_id' => $this->appId,
            'auth_mode' => $this->authMode,
            'user_id' => $this->userId,
            'client_id' => $this->clientId,
            'tenant_id' => $this->tenantId,
            'scopes' => $this->scopes,
            'capabilities' => $this->capabilities,
            'metadata' => $this->metadata,
            'device_id' => $this->deviceId,
            'ip_address' => $this->ipAddress,
            'request_id' => $this->getRequestId(),
            'is_authenticated' => $this->isAuthenticated(),
        ];
    }

    public function toJson($options = 0): string
    {
        return json_encode($this->toArray(), $options | JSON_THROW_ON_ERROR);
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    public function __toString(): string
    {
        return $this->toJson();
    }
}
