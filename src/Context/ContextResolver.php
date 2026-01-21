<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Context;

use Charlietyn\AppContext\Contracts\ContextResolverInterface;
use Illuminate\Http\Request;

/**
 * Resolves AppContext from incoming HTTP requests based on host/path patterns.
 *
 * SECURITY: Never trusts unsigned headers (X-App, X-Channel).
 * Detection is based only on:
 * - Host (subdomain extraction)
 * - Request path (prefix matching)
 */
final class ContextResolver implements ContextResolverInterface
{
    private readonly array $channels;
    private readonly string $domain;
    private readonly string $detectionStrategy;
    private readonly array $autoDetectionRules;
    private readonly array $devContexts;
    private readonly bool $denyByDefault;

    public function __construct(array $config)
    {
        $this->channels = $config['channels'] ?? [];
        $this->domain = $config['domain'] ?? 'localhost';
        $this->detectionStrategy = $config['detection_strategy'] ?? 'auto';
        $this->autoDetectionRules = $config['auto_detection_rules'] ?? [];
        $this->devContexts = $config['app_context_dev'] ?? ['local'];
        $this->denyByDefault = $config['deny_by_default'] ?? true;
    }

    /**
     * Resolve the application context from the request.
     */
    public function resolve(Request $request): ?AppContext
    {
        $context = match ($this->detectionStrategy) {
            'path' => $this->resolveByPath($request),
            'subdomain' => $this->resolveBySubdomain($request),
            'strict' => $this->resolveStrict($request),
            default => $this->resolveAuto($request),
        };

        return $context;
    }

    /**
     * Resolve context using path-based detection only.
     */
    public function resolveByPath(Request $request): ?AppContext
    {
        $path = '/' . ltrim($request->path(), '/');
        $channelId = $this->matchPathPrefix($path);

        if ($channelId === null) {
            return null;
        }

        return $this->createContext($channelId, $request);
    }

    /**
     * Resolve context using subdomain-based detection only.
     */
    public function resolveBySubdomain(Request $request): ?AppContext
    {
        $host = $request->getHost();
        $subdomain = $this->extractSubdomain($host);
        $channelId = $this->matchSubdomain($subdomain);

        if ($channelId === null) {
            return null;
        }

        return $this->createContext($channelId, $request);
    }

    /**
     * Resolve context using strict mode (both path and subdomain must match).
     */
    public function resolveStrict(Request $request): ?AppContext
    {
        $host = $request->getHost();
        $path = '/' . ltrim($request->path(), '/');

        $subdomain = $this->extractSubdomain($host);
        $subdomainChannel = $this->matchSubdomain($subdomain);
        $pathChannel = $this->matchPathPrefix($path);

        // Both must match the same channel
        if ($subdomainChannel === null || $pathChannel === null) {
            return null;
        }

        if ($subdomainChannel !== $pathChannel) {
            return null;
        }

        return $this->createContext($subdomainChannel, $request);
    }

    /**
     * Resolve context using auto-detection based on host rules.
     */
    public function resolveAuto(Request $request): ?AppContext
    {
        $host = $request->getHost();
        $strategy = $this->getDetectionStrategy($host);

        return match ($strategy) {
            'path' => $this->resolveByPath($request),
            'subdomain' => $this->resolveBySubdomain($request),
            'strict' => $this->resolveStrict($request),
            default => $this->resolveByPath($request) ?? $this->resolveBySubdomain($request),
        };
    }

    /**
     * Get the detection strategy for a given host.
     */
    public function getDetectionStrategy(string $host): string
    {
        // Check explicit rules first
        foreach ($this->autoDetectionRules as $pattern => $strategy) {
            if ($this->hostMatchesPattern($host, $pattern)) {
                return $strategy;
            }
        }

        // Check if it's a development context
        if ($this->isDevContext()) {
            return 'path';
        }

        // Default to subdomain for production
        return 'subdomain';
    }

    /**
     * Extract subdomain from host.
     */
    public function extractSubdomain(string $host): ?string
    {
        // Remove port if present
        $host = preg_replace('/:\d+$/', '', $host);

        // Handle localhost and IP addresses
        if ($host === 'localhost' || filter_var($host, FILTER_VALIDATE_IP)) {
            return null;
        }

        // Handle special development domains (*.localhost, *.test, etc.)
        if (preg_match('/^([^.]+)\.(localhost|test|local)$/', $host, $matches)) {
            return $matches[1];
        }

        // Extract subdomain from domain
        $domain = preg_quote($this->domain, '/');
        if (preg_match('/^([^.]+)\.' . $domain . '$/', $host, $matches)) {
            return $matches[1];
        }

        // Handle www or no subdomain
        if ($host === $this->domain || $host === "www.{$this->domain}") {
            return null; // Will match 'site' channel with null subdomain
        }

        // Multi-level subdomain extraction (admin.api.example.com -> admin)
        $parts = explode('.', $host);
        if (count($parts) > 2) {
            return $parts[0];
        }

        return null;
    }

    /**
     * Match path prefix to channel.
     */
    public function matchPathPrefix(string $path): ?string
    {
        $path = '/' . ltrim($path, '/');

        foreach ($this->channels as $channelId => $config) {
            $prefixes = $config['path_prefixes'] ?? [];

            foreach ($prefixes as $prefix) {
                $prefix = '/' . ltrim($prefix, '/');

                if (str_starts_with($path, $prefix)) {
                    return $channelId;
                }
            }
        }

        return null;
    }

    /**
     * Match subdomain to channel.
     */
    private function matchSubdomain(?string $subdomain): ?string
    {
        foreach ($this->channels as $channelId => $config) {
            $subdomains = $config['subdomains'] ?? [];

            // Handle null subdomain (root domain or www)
            if ($subdomain === null && in_array(null, $subdomains, true)) {
                return $channelId;
            }

            // Handle www as null equivalent
            if ($subdomain === 'www' && in_array(null, $subdomains, true)) {
                return $channelId;
            }

            if (in_array($subdomain, $subdomains, true)) {
                return $channelId;
            }
        }

        return null;
    }

    /**
     * Create AppContext for a resolved channel.
     */
    private function createContext(string $channelId, Request $request): AppContext
    {
        $config = $this->channels[$channelId] ?? [];
        $authMode = $config['auth_mode'] ?? 'jwt';

        return AppContext::fromChannel(
            appId: $channelId,
            authMode: $authMode,
            ipAddress: $request->ip(),
            requestId: $request->header('X-Request-ID'),
        );
    }

    /**
     * Check if host matches a pattern (supports wildcards).
     */
    private function hostMatchesPattern(string $host, string $pattern): bool
    {
        // Convert pattern to regex
        $regex = str_replace(
            ['.', '*'],
            ['\.', '[^.]+'],
            $pattern
        );

        return (bool) preg_match('/^' . $regex . '$/', $host);
    }

    /**
     * Check if current environment is a development context.
     */
    private function isDevContext(): bool
    {
        $appEnv = config('app.env', 'production');

        return in_array($appEnv, $this->devContexts, true);
    }

    /**
     * Get channel configuration.
     */
    public function getChannelConfig(string $channelId): ?array
    {
        return $this->channels[$channelId] ?? null;
    }

    /**
     * Get all configured channels.
     */
    public function getChannels(): array
    {
        return $this->channels;
    }

    /**
     * Check if deny by default is enabled.
     */
    public function isDenyByDefault(): bool
    {
        return $this->denyByDefault;
    }
}
