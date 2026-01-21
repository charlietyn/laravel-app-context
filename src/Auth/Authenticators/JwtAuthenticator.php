<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Auth\Authenticators;

use Charlietyn\AppContext\Auth\Verifiers\JwtVerifier;
use Charlietyn\AppContext\Context\AppContext;
use Charlietyn\AppContext\Contracts\AuthenticatorInterface;
use Charlietyn\AppContext\Exceptions\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 * JWT Authenticator for user-based authentication.
 */
final class JwtAuthenticator implements AuthenticatorInterface
{
    private readonly array $publicRoutes;
    private readonly array $channels;

    public function __construct(
        private readonly JwtVerifier $verifier,
        array $config,
    ) {
        $this->publicRoutes = $config['public_routes'] ?? [];
        $this->channels = $config['channels'] ?? [];
    }

    /**
     * Authenticate the request and return enriched AppContext.
     */
    public function authenticate(Request $request, AppContext $context): AppContext
    {
        // Check if this is a public route
        if (! $this->isRequired($request, $context)) {
            // For jwt_or_anonymous, try to authenticate but don't fail
            if ($context->getAuthMode() === 'jwt_or_anonymous') {
                return $this->tryAuthenticate($request, $context);
            }

            return $context;
        }

        // Verify JWT
        $claims = $this->verifier->verify($request);

        // Load user
        $user = $this->loadUser($claims['sub']);
        if ($user === null) {
            throw AuthenticationException::userNotFound();
        }

        // Set user in auth
        Auth::setUser($user);

        // Build scopes
        $scopes = $this->buildScopes($claims, $user, $context);

        // Create enriched context
        return AppContext::fromJwt(
            appId: $context->getAppId(),
            claims: array_merge($claims, ['scp' => $scopes]),
            ipAddress: $context->getIpAddress(),
            requestId: $context->getRequestId(),
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
        // Check if route is public
        if ($this->isPublicRoute($request)) {
            return false;
        }

        // Check if channel allows anonymous
        $channelConfig = $this->channels[$context->getAppId()] ?? [];
        if ($channelConfig['features']['allow_anonymous'] ?? false) {
            return false;
        }

        return true;
    }

    /**
     * Get the authentication modes this authenticator handles.
     */
    public function getAuthModes(): array
    {
        return ['jwt', 'jwt_or_anonymous'];
    }

    /**
     * Try to authenticate without failing (for optional auth).
     */
    private function tryAuthenticate(Request $request, AppContext $context): AppContext
    {
        try {
            if (! $this->verifier->canHandle($request)) {
                // No token provided, return anonymous context
                return AppContext::anonymous(
                    appId: $context->getAppId(),
                    ipAddress: $context->getIpAddress(),
                    requestId: $context->getRequestId(),
                );
            }

            return $this->authenticate($request, $context);
        } catch (AuthenticationException) {
            // Token invalid, return anonymous context
            return AppContext::anonymous(
                appId: $context->getAppId(),
                ipAddress: $context->getIpAddress(),
                requestId: $context->getRequestId(),
            );
        }
    }

    /**
     * Load user by ID.
     */
    private function loadUser(int|string $userId): ?Authenticatable
    {
        $provider = Auth::getProvider();

        return $provider?->retrieveById($userId);
    }

    /**
     * Build scopes from JWT claims, user permissions, and channel config.
     */
    private function buildScopes(array $claims, Authenticatable $user, AppContext $context): array
    {
        // Priority 1: Scopes from JWT
        if (! empty($claims['scp'])) {
            return is_array($claims['scp']) ? $claims['scp'] : explode(' ', $claims['scp']);
        }

        // Priority 2: Build from user permissions and channel
        $scopes = [];

        // Get channel allowed scopes
        $channelConfig = $this->channels[$context->getAppId()] ?? [];
        $allowedScopes = $channelConfig['allowed_scopes'] ?? [];

        // Get user permissions if method exists
        if (method_exists($user, 'getPermissions')) {
            $userPermissions = $user->getPermissions();

            // Filter by channel allowed scopes
            foreach ($userPermissions as $permission) {
                foreach ($allowedScopes as $allowed) {
                    if ($this->scopeMatches($permission, $allowed)) {
                        $scopes[] = $permission;
                        break;
                    }
                }
            }
        }

        // If no specific permissions, grant channel default
        if (empty($scopes) && ! empty($allowedScopes)) {
            // Don't grant wildcards by default, use specific defaults
            $scopes = array_filter($allowedScopes, fn ($s) => ! str_contains($s, '*'));
        }

        return array_unique($scopes);
    }

    /**
     * Check if a permission matches an allowed scope pattern.
     */
    private function scopeMatches(string $permission, string $allowed): bool
    {
        if ($permission === $allowed) {
            return true;
        }

        // Wildcard matching: admin:* matches admin:users:read
        if (str_ends_with($allowed, ':*')) {
            $prefix = substr($allowed, 0, -1); // Remove '*'

            return str_starts_with($permission, $prefix);
        }

        return false;
    }

    /**
     * Check if the current route is public.
     */
    private function isPublicRoute(Request $request): bool
    {
        $route = $request->route();

        // Check by route name
        if ($route !== null) {
            $name = $route->getName();

            if ($name !== null) {
                // Exact match
                if (in_array($name, $this->publicRoutes['names'] ?? [], true)) {
                    return true;
                }

                // Name ending match
                foreach ($this->publicRoutes['name_endings'] ?? [] as $ending) {
                    if (str_ends_with($name, $ending)) {
                        return true;
                    }
                }
            }
        }

        // Check by path ending
        $path = '/' . ltrim($request->path(), '/');
        foreach ($this->publicRoutes['path_endings'] ?? [] as $ending) {
            if (str_ends_with($path, $ending)) {
                return true;
            }
        }

        return false;
    }
}
