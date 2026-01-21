<?php

declare(strict_types=1);

namespace Ronu\AppContext\Auth\Guards;

use Ronu\AppContext\Context\AppContext;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;

/**
 * Custom guard that integrates with AppContext.
 */
class AppContextGuard implements Guard
{
    protected ?Authenticatable $user = null;

    public function __construct(
        protected readonly string $name,
        protected readonly ?UserProvider $provider,
        protected readonly Request $request,
    ) {}

    /**
     * Determine if the current user is authenticated.
     */
    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * Determine if the current user is a guest.
     */
    public function guest(): bool
    {
        return ! $this->check();
    }

    /**
     * Get the currently authenticated user.
     */
    public function user(): ?Authenticatable
    {
        if ($this->user !== null) {
            return $this->user;
        }

        // Try to get from AppContext
        $context = $this->getAppContext();
        if ($context === null || ! $context->isAuthenticated()) {
            return null;
        }

        $userId = $context->getUserId();
        if ($userId === null) {
            return null;
        }

        // Load user from provider
        $this->user = $this->provider?->retrieveById($userId);

        return $this->user;
    }

    /**
     * Get the ID for the currently authenticated user.
     */
    public function id(): int|string|null
    {
        $context = $this->getAppContext();

        return $context?->getUserId();
    }

    /**
     * Validate a user's credentials.
     */
    public function validate(array $credentials = []): bool
    {
        if ($this->provider === null) {
            return false;
        }

        $user = $this->provider->retrieveByCredentials($credentials);

        return $user !== null && $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * Determine if the guard has a user instance.
     */
    public function hasUser(): bool
    {
        return $this->user !== null;
    }

    /**
     * Set the current user.
     */
    public function setUser(Authenticatable $user): static
    {
        $this->user = $user;

        return $this;
    }

    /**
     * Get the AppContext from the request.
     */
    protected function getAppContext(): ?AppContext
    {
        return $this->request->attributes->get('app_context');
    }

    /**
     * Get the user provider.
     */
    public function getProvider(): ?UserProvider
    {
        return $this->provider;
    }

    /**
     * Set the user provider.
     */
    public function setProvider(UserProvider $provider): static
    {
        $this->provider = $provider;

        return $this;
    }
}
