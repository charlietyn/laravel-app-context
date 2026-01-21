<?php

declare(strict_types=1);

namespace Charlietyn\AppContext\Exceptions;

use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Base exception for all AppContext errors.
 */
class AppContextException extends Exception
{
    protected string $errorCode = 'APP_CONTEXT_ERROR';
    protected int $httpStatus = 500;

    public function __construct(
        string $message = 'An error occurred',
        protected readonly ?string $context = null,
        ?Exception $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    /**
     * Get the error code.
     */
    public function getErrorCode(): string
    {
        return $this->errorCode;
    }

    /**
     * Get the HTTP status code.
     */
    public function getHttpStatus(): int
    {
        return $this->httpStatus;
    }

    /**
     * Get additional context.
     */
    public function getContext(): ?string
    {
        return $this->context;
    }

    /**
     * Render the exception as an HTTP response.
     */
    public function render(Request $request): JsonResponse
    {
        return response()->json([
            'error' => $this->errorCode,
            'message' => $this->getMessage(),
            'context' => $this->context,
        ], $this->httpStatus);
    }

    /**
     * Report the exception.
     */
    public function report(): bool
    {
        // Don't report by default, let subclasses override
        return false;
    }
}
