<?php

declare(strict_types=1);

namespace Ronu\AppContext\Contracts;

use Ronu\AppContext\Context\AppContext;
use Illuminate\Http\Request;

interface AuthenticatorInterface
{
    /**
     * Authenticate the request and return an enriched AppContext.
     *
     * @param Request $request The incoming HTTP request
     * @param AppContext $context The initial context from resolver
     * @return AppContext The enriched context with authentication details
     *
     * @throws \Ronu\AppContext\Exceptions\AuthenticationException
     */
    public function authenticate(Request $request, AppContext $context): AppContext;

    /**
     * Check if this authenticator supports the given auth mode.
     */
    public function supports(string $authMode): bool;

    /**
     * Check if authentication is required for this request.
     */
    public function isRequired(Request $request, AppContext $context): bool;

    /**
     * Get the authentication mode this authenticator handles.
     *
     * @return array<string>
     */
    public function getAuthModes(): array;
}
