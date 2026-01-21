<?php

declare(strict_types=1);

namespace Ronu\AppContext\Support;

/**
 * Utility class for checking scopes and capabilities with wildcard support.
 */
final class ScopeChecker
{
    /**
     * Check if the given scopes contain a required scope.
     * Supports wildcards: admin:* matches admin:users:read
     */
    public function hasScope(array $scopes, string $required): bool
    {
        // Exact match
        if (in_array($required, $scopes, true)) {
            return true;
        }

        // Wildcard matching
        foreach ($scopes as $scope) {
            if ($this->scopeMatches($scope, $required)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if any of the required scopes are present.
     */
    public function hasAnyScope(array $scopes, array $required): bool
    {
        foreach ($required as $scope) {
            if ($this->hasScope($scopes, $scope)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if all required scopes are present.
     */
    public function hasAllScopes(array $scopes, array $required): bool
    {
        foreach ($required as $scope) {
            if (! $this->hasScope($scopes, $scope)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if a scope pattern matches a required scope.
     *
     * Patterns:
     * - Exact: 'admin:users:read' matches 'admin:users:read'
     * - Wildcard suffix: 'admin:*' matches 'admin:users:read', 'admin:settings'
     * - Multi-level wildcard: 'admin:users:*' matches 'admin:users:read', 'admin:users:write'
     */
    public function scopeMatches(string $pattern, string $scope): bool
    {
        // Exact match
        if ($pattern === $scope) {
            return true;
        }

        // Wildcard matching
        if (str_ends_with($pattern, ':*')) {
            $prefix = substr($pattern, 0, -1); // Remove '*', keep ':'

            return str_starts_with($scope, $prefix);
        }

        // Super wildcard (just '*' matches everything)
        if ($pattern === '*') {
            return true;
        }

        return false;
    }

    /**
     * Filter scopes to only those allowed by a pattern list.
     */
    public function filterScopes(array $scopes, array $allowedPatterns): array
    {
        return array_filter($scopes, function ($scope) use ($allowedPatterns) {
            foreach ($allowedPatterns as $pattern) {
                if ($this->scopeMatches($pattern, $scope) || $this->scopeMatches($scope, $pattern)) {
                    return true;
                }
            }

            return false;
        });
    }

    /**
     * Expand a wildcard scope into concrete scopes based on a list.
     */
    public function expandWildcard(string $pattern, array $availableScopes): array
    {
        if (! str_contains($pattern, '*')) {
            return [$pattern];
        }

        return array_filter($availableScopes, fn ($scope) => $this->scopeMatches($pattern, $scope));
    }

    /**
     * Parse a scope string into parts.
     *
     * @return array{channel: string|null, resource: string|null, action: string|null}
     */
    public function parseScope(string $scope): array
    {
        $parts = explode(':', $scope);

        return [
            'channel' => $parts[0] ?? null,
            'resource' => $parts[1] ?? null,
            'action' => $parts[2] ?? null,
        ];
    }

    /**
     * Build a scope string from parts.
     */
    public function buildScope(?string $channel, ?string $resource = null, ?string $action = null): string
    {
        $parts = array_filter([$channel, $resource, $action], fn ($p) => $p !== null);

        return implode(':', $parts);
    }
}
