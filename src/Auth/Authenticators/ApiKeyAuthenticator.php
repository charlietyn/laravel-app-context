<?php

declare(strict_types=1);

namespace Ronu\AppContext\Auth\Authenticators;

use Ronu\AppContext\Auth\Verifiers\ApiKeyVerifier;
use Ronu\AppContext\Context\AppContext;
use Ronu\AppContext\Contracts\AuthenticatorInterface;
use Illuminate\Http\Request;

/**
 * API Key Authenticator for B2B/Partner authentication.
 */
final class ApiKeyAuthenticator implements AuthenticatorInterface
{
    private readonly array $channels;

    public function __construct(
        private readonly ApiKeyVerifier $verifier,
        array $config,
    ) {
        $this->channels = $config['channels'] ?? [];
    }

    /**
     * Authenticate the request and return enriched AppContext.
     */
    public function authenticate(Request $request, AppContext $context): AppContext
    {
        // Verify API key
        $verification = $this->verifier->verify($request);

        // Build capabilities (filter by channel config)
        $capabilities = $this->buildCapabilities(
            $verification['capabilities'],
            $context->getAppId()
        );

        // Create enriched context
        return AppContext::fromApiKey(
            appId: $context->getAppId(),
            clientId: $verification['client_id'],
            capabilities: $capabilities,
            tenantId: $verification['tenant_id'],
            ipAddress: $context->getIpAddress(),
            requestId: $context->getRequestId(),
            metadata: $verification['metadata'],
        );
    }

    /**
     * Check if this authenticator supports the given auth mode.
     */
    public function supports(string $authMode): bool
    {
        return in_array($authMode, $this->getAuthModes(), true);
    }

    /**
     * Check if authentication is required for this request.
     */
    public function isRequired(Request $request, AppContext $context): bool
    {
        // API key authentication is always required for api_key channels
        return true;
    }

    /**
     * Get the authentication modes this authenticator handles.
     */
    public function getAuthModes(): array
    {
        return ['api_key'];
    }

    /**
     * Build capabilities filtered by channel configuration.
     */
    private function buildCapabilities(array $clientCapabilities, string $channelId): array
    {
        $channelConfig = $this->channels[$channelId] ?? [];
        $allowedCapabilities = $channelConfig['allowed_capabilities'] ?? [];

        // If no channel restrictions, return all client capabilities
        if (empty($allowedCapabilities)) {
            return $clientCapabilities;
        }

        // Filter capabilities by what the channel allows
        $capabilities = [];

        foreach ($clientCapabilities as $capability) {
            foreach ($allowedCapabilities as $allowed) {
                if ($this->capabilityMatches($capability, $allowed)) {
                    $capabilities[] = $capability;
                    break;
                }
            }
        }

        return array_unique($capabilities);
    }

    /**
     * Check if a capability matches an allowed pattern.
     */
    private function capabilityMatches(string $capability, string $allowed): bool
    {
        if ($capability === $allowed) {
            return true;
        }

        // Wildcard matching: partner:* matches partner:orders:create
        if (str_ends_with($allowed, ':*')) {
            $prefix = substr($allowed, 0, -1); // Remove '*'

            return str_starts_with($capability, $prefix);
        }

        return false;
    }
}
