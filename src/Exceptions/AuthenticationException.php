<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Exceptions;

/**
 * Exception thrown when authentication fails.
 */
class AuthenticationException extends AppContextException
{
    protected string $errorCode = 'AUTHENTICATION_FAILED';
    protected int $httpStatus = 401;

    public static function invalidToken(string $reason = 'Invalid or expired token'): self
    {
        return new self($reason, 'jwt_verification');
    }

    public static function missingToken(): self
    {
        return new self('Authentication required', 'missing_credentials');
    }

    public static function invalidApiKey(string $reason = 'Invalid API key'): self
    {
        return new self($reason, 'api_key_verification');
    }

    public static function missingApiKey(): self
    {
        return new self('API key required', 'missing_api_key');
    }

    public static function expiredApiKey(): self
    {
        return new self('API key has expired', 'expired_api_key');
    }

    public static function revokedApiKey(): self
    {
        return new self('API key has been revoked', 'revoked_api_key');
    }

    public static function blacklistedToken(): self
    {
        return new self('Token has been blacklisted', 'blacklisted_token');
    }

    public static function algorithmMismatch(string $algorithm): self
    {
        return new self(
            "Algorithm '{$algorithm}' is not allowed",
            'algorithm_mismatch'
        );
    }

    public static function ipNotAllowed(string $ip): self
    {
        return new self(
            "IP address '{$ip}' is not in the allowlist",
            'ip_not_allowed'
        );
    }

    public static function userNotFound(): self
    {
        return new self('User not found', 'user_not_found');
    }

    public static function clientNotFound(): self
    {
        return new self('API client not found', 'client_not_found');
    }
}
