<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Auth\Authenticators;

use Charlietyn\AppContext\Context\AppContext;
use Charlietyn\AppContext\Contracts\AuthenticatorInterface;
use Illuminate\Http\Request;

/**
 * Anonymous Authenticator for public access.
 */
final class AnonymousAuthenticator implements AuthenticatorInterface
{
    private const DEFAULT_SCOPES = ['public:read', 'catalog:browse'];

    private readonly array $channels;

    public function __construct(array $config)
    {
        $this->channels = $config['channels'] ?? [];
    }

    /**
     * Authenticate the request and return enriched AppContext.
     */
    public function authenticate(Request $request, AppContext $context): AppContext
    {
        $scopes = $this->getAnonymousScopes($context->getAppId());

        return AppContext::anonymous(
            appId: $context->getAppId(),
            ipAddress: $context->getIpAddress(),
            requestId: $context->getRequestId(),
        )->withScopes($scopes);
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
        // Anonymous authentication is never "required"
        return false;
    }

    /**
     * Get the authentication modes this authenticator handles.
     */
    public function getAuthModes(): array
    {
        return ['anonymous'];
    }

    /**
     * Get scopes for anonymous access based on channel config.
     */
    private function getAnonymousScopes(string $channelId): array
    {
        $channelConfig = $this->channels[$channelId] ?? [];
        $allowedScopes = $channelConfig['allowed_scopes'] ?? [];

        // Filter to only non-wildcard, public-safe scopes
        $publicScopes = array_filter($allowedScopes, function ($scope) {
            // Only allow specific public scopes, not wildcards
            if (str_contains($scope, '*')) {
                return false;
            }

            // Allow scopes that are explicitly public
            return str_starts_with($scope, 'public:')
                || str_starts_with($scope, 'catalog:')
                || in_array($scope, self::DEFAULT_SCOPES, true);
        });

        return ! empty($publicScopes) ? array_values($publicScopes) : self::DEFAULT_SCOPES;
    }
}
