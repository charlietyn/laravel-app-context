<?php

declare(strict_types=1);

namespace Ronu\AppContext\Facades;

use Ronu\AppContext\Context\AppContext as AppContextInstance;
use Illuminate\Support\Facades\Facade;

/**
 * @method static string|null getAppId()
 * @method static string|null getAuthMode()
 * @method static int|string|null getUserId()
 * @method static string|null getClientId()
 * @method static string|null getTenantId()
 * @method static array getScopes()
 * @method static array getCapabilities()
 * @method static array getMetadata()
 * @method static string|null getDeviceId()
 * @method static string|null getIpAddress()
 * @method static string getRequestId()
 * @method static bool isAuthenticated()
 * @method static bool isAnonymous()
 * @method static bool hasScope(string $scope)
 * @method static bool hasCapability(string $capability)
 * @method static bool hasAbility(string $ability)
 * @method static bool hasAnyScope(array $scopes)
 * @method static bool hasAllScopes(array $scopes)
 * @method static bool hasAnyAbility(array $abilities)
 * @method static bool hasAllAbilities(array $abilities)
 * @method static void requires(string $scopeOrCapability)
 * @method static string getRateLimitKey()
 * @method static array toLogContext()
 * @method static array toArray()
 * @method static AppContextInstance withUserId(int|string $userId)
 * @method static AppContextInstance withClientId(string $clientId)
 * @method static AppContextInstance withTenantId(string $tenantId)
 * @method static AppContextInstance withScopes(array $scopes)
 * @method static AppContextInstance withCapabilities(array $capabilities)
 * @method static AppContextInstance withMetadata(array $metadata)
 * @method static AppContextInstance addMetadata(string $key, mixed $value)
 *
 * @see \Ronu\AppContext\Context\AppContext
 */
class AppContext extends Facade
{
    /**
     * Get the registered name of the component.
     */
    protected static function getFacadeAccessor(): string
    {
        return 'app-context';
    }

    /**
     * Get the current context from the request.
     */
    public static function current(): ?AppContextInstance
    {
        return request()->attributes->get('app_context');
    }

    /**
     * Check if context is resolved.
     */
    public static function isResolved(): bool
    {
        return request()->attributes->has('app_context');
    }

    /**
     * Get channel configuration.
     */
    public static function getChannelConfig(?string $channel = null): ?array
    {
        $channel ??= static::current()?->getAppId();

        if ($channel === null) {
            return null;
        }

        return config("app-context.channels.{$channel}");
    }

    /**
     * Check if current channel has a specific feature enabled.
     */
    public static function hasFeature(string $feature): bool
    {
        $config = static::getChannelConfig();

        return $config['features'][$feature] ?? false;
    }
}
