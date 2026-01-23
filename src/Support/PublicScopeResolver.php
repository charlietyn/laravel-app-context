<?php

declare(strict_types=1);

namespace Ronu\AppContext\Support;

/**
 * Resolve public-safe scopes for anonymous or optional-auth contexts.
 */
final class PublicScopeResolver
{
    private const DEFAULT_SCOPES = ['public:read', 'catalog:browse'];

    /**
     * Resolve public scopes for a channel.
     */
    public static function resolve(array $channelConfig): array
    {
        $explicit = $channelConfig['public_scopes'] ?? [];
        if (! empty($explicit)) {
            return array_values($explicit);
        }

        $allowedScopes = $channelConfig['allowed_scopes'] ?? [];

        // Filter to only non-wildcard, public-safe scopes
        $publicScopes = array_filter($allowedScopes, function ($scope) {
            if (str_contains($scope, '*')) {
                return false;
            }

            return str_starts_with($scope, 'public:')
                || str_starts_with($scope, 'catalog:')
                || in_array($scope, self::DEFAULT_SCOPES, true);
        });

        return ! empty($publicScopes) ? array_values($publicScopes) : self::DEFAULT_SCOPES;
    }
}
