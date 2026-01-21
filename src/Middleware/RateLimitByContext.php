<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Middleware;

use Charlietyn\AppContext\Context\AppContext;
use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware that applies rate limiting based on AppContext.
 *
 * Rate limits are configured per channel and can vary by:
 * - User (authenticated requests)
 * - Client ID (API key requests)
 * - IP (anonymous requests)
 * - User + Device (mobile)
 */
class RateLimitByContext
{
    public function __construct(
        protected readonly RateLimiter $limiter,
    ) {}

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        /** @var AppContext|null $context */
        $context = $request->attributes->get('app_context');

        if ($context === null) {
            return $next($request);
        }

        // Get rate limit configuration
        $config = $this->getRateLimitConfig($context, $request);

        if ($config === null) {
            return $next($request);
        }

        // Parse limit (e.g., "60/m" -> 60 per minute)
        [$maxAttempts, $decaySeconds] = $this->parseLimit($config['limit']);

        // Get the rate limit key
        $key = $this->getRateLimitKey($context, $config['by']);

        // Check rate limit
        if ($this->limiter->tooManyAttempts($key, $maxAttempts)) {
            $retryAfter = $this->limiter->availableIn($key);

            throw new ThrottleRequestsException(
                message: 'Too Many Attempts.',
                headers: [
                    'Retry-After' => $retryAfter,
                    'X-RateLimit-Limit' => $maxAttempts,
                    'X-RateLimit-Remaining' => 0,
                ]
            );
        }

        // Increment attempts
        $this->limiter->hit($key, $decaySeconds);

        $response = $next($request);

        // Add rate limit headers
        return $this->addHeaders(
            $response,
            $maxAttempts,
            $this->limiter->remaining($key, $maxAttempts)
        );
    }

    /**
     * Get rate limit configuration for the context.
     */
    protected function getRateLimitConfig(AppContext $context, Request $request): ?array
    {
        $channelId = $context->getAppId();
        $profile = config("app-context.rate_limits.{$channelId}");

        if ($profile === null) {
            return null;
        }

        // Check for endpoint-specific limit
        $method = $request->method();
        $path = '/' . ltrim($request->path(), '/');
        $endpointKey = "{$method}:{$path}";

        foreach ($profile['endpoints'] ?? [] as $pattern => $limit) {
            if ($this->matchEndpoint($endpointKey, $pattern)) {
                return [
                    'limit' => $limit,
                    'by' => $profile['by'] ?? 'ip',
                ];
            }
        }

        // Use global limit
        $limit = $context->isAuthenticated()
            ? ($profile['authenticated_global'] ?? $profile['global'] ?? '60/m')
            : ($profile['global'] ?? '30/m');

        return [
            'limit' => $limit,
            'by' => $profile['by'] ?? 'ip',
        ];
    }

    /**
     * Get the rate limit key based on context.
     */
    protected function getRateLimitKey(AppContext $context, string $by): string
    {
        $prefix = "rate_limit:{$context->getAppId()}";

        return match ($by) {
            'user' => "{$prefix}:user:{$context->getUserId()}",
            'client_id' => "{$prefix}:client:{$context->getClientId()}",
            'ip' => "{$prefix}:ip:{$context->getIpAddress()}",
            'user_device' => "{$prefix}:user:{$context->getUserId()}:device:{$context->getDeviceId()}",
            'ip_or_user' => $context->isAuthenticated()
                ? "{$prefix}:user:{$context->getUserId()}"
                : "{$prefix}:ip:{$context->getIpAddress()}",
            default => $context->getRateLimitKey(),
        };
    }

    /**
     * Parse a limit string (e.g., "60/m" -> [60, 60]).
     *
     * @return array{0: int, 1: int} [maxAttempts, decaySeconds]
     */
    protected function parseLimit(string $limit): array
    {
        $parts = explode('/', $limit);
        $maxAttempts = (int) $parts[0];

        $period = $parts[1] ?? 'm';
        $decaySeconds = match ($period) {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            default => 60,
        };

        return [$maxAttempts, $decaySeconds];
    }

    /**
     * Match an endpoint against a pattern (supports wildcards).
     */
    protected function matchEndpoint(string $endpoint, string $pattern): bool
    {
        // Exact match
        if ($endpoint === $pattern) {
            return true;
        }

        // Convert pattern to regex (supports * wildcard)
        $regex = str_replace(
            ['/', '*'],
            ['\/', '[^\/]+'],
            $pattern
        );

        return (bool) preg_match("/^{$regex}$/", $endpoint);
    }

    /**
     * Add rate limit headers to response.
     */
    protected function addHeaders(Response $response, int $maxAttempts, int $remaining): Response
    {
        $response->headers->set('X-RateLimit-Limit', (string) $maxAttempts);
        $response->headers->set('X-RateLimit-Remaining', (string) max(0, $remaining));

        return $response;
    }
}
