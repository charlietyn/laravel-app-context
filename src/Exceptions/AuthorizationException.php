<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Exceptions;

/**
 * Exception thrown when authorization fails (missing scope/capability).
 */
class AuthorizationException extends AppContextException
{
    protected string $errorCode = 'AUTHORIZATION_FAILED';
    protected int $httpStatus = 403;

    /**
     * @param string $message The error message
     * @param string|array $required The required permission(s)
     */
    public function __construct(
        string $message,
        protected readonly string|array $required,
    ) {
        parent::__construct($message, is_array($required) ? implode(', ', $required) : $required);
    }

    /**
     * Get the required permission(s).
     */
    public function getRequired(): string|array
    {
        return $this->required;
    }

    public static function missingScope(string $scope): self
    {
        return new self("Missing required scope: {$scope}", $scope);
    }

    public static function missingCapability(string $capability): self
    {
        return new self("Missing required capability: {$capability}", $capability);
    }

    public static function missingAnyPermission(array $permissions): self
    {
        $list = implode(', ', $permissions);

        return new self("Missing required permission. Required one of: {$list}", $permissions);
    }

    public static function insufficientPermissions(): self
    {
        return new self('Insufficient permissions for this action', 'unknown');
    }
}
