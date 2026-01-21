<?php

declare(strict_types=1);

namespace Ronu\AppContext\Exceptions;

/**
 * Exception thrown when context binding validation fails.
 */
class ContextBindingException extends AppContextException
{
    protected string $errorCode = 'CONTEXT_BINDING_FAILED';
    protected int $httpStatus = 403;

    public static function audienceMismatch(string $expected, string $actual): self
    {
        return new self(
            "Token audience mismatch. Expected '{$expected}', got '{$actual}'",
            'audience_binding'
        );
    }

    public static function channelMismatch(string $expected, string $actual): self
    {
        return new self(
            "Client not authorized for channel '{$expected}'. Configured for '{$actual}'",
            'channel_binding'
        );
    }

    public static function tenantMismatch(string $expected, string $actual): self
    {
        return new self(
            "Tenant mismatch. Token tenant '{$actual}' cannot access tenant '{$expected}'",
            'tenant_binding'
        );
    }

    public static function missingTenant(): self
    {
        return new self(
            'Tenant ID required but not present in token',
            'missing_tenant'
        );
    }

    public static function unknownChannel(string $channel): self
    {
        return new self(
            "Unknown channel: {$channel}",
            'unknown_channel'
        );
    }

    public static function denyByDefault(): self
    {
        return new self(
            'Request does not match any configured channel',
            'deny_by_default'
        );
    }
}
