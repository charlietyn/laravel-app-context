<?php

declare(strict_types=1);

namespace Ronu\AppContext\Contracts;

use Illuminate\Http\Request;

interface VerifierInterface
{
    /**
     * Verify credentials from the request.
     *
     * @param Request $request The incoming HTTP request
     * @return array The verification result with claims/capabilities
     *
     * @throws \Ronu\AppContext\Exceptions\AuthenticationException
     */
    public function verify(Request $request): array;

    /**
     * Check if this verifier can handle the request.
     */
    public function canHandle(Request $request): bool;

    /**
     * Get the credential type this verifier handles.
     */
    public function getCredentialType(): string;
}
