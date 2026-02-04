# Public API

This section summarizes the primary public classes and helper utilities exposed by the package.

## Facade: `Ronu\AppContext\Facades\AppContext`

Key methods:
- `getAppId()`, `getAuthMode()`, `getUserId()`, `getClientId()`, `getTenantId()`
- `getScopes()`, `getCapabilities()`, `hasScope()`, `hasCapability()`, `hasAbility()`
- `isAuthenticated()`, `isAnonymous()`
- `toArray()`
- `current()` (returns the context from the request)
- `isResolved()`

## Core value object: `Ronu\AppContext\Context\AppContext`

Key factory methods:
- `fromChannel()`
- `fromJwt()`
- `fromApiKey()`
- `anonymous()`

Key authorization methods:
- `hasScope()`, `hasCapability()`, `hasAbility()`
- `requires()`, `requiresAny()`, `requiresAll()`

Key utility methods:
- `getRateLimitKey()`
- `toLogContext()`

## Context resolution

`Ronu\AppContext\Context\ContextResolver` implements `ContextResolverInterface` and exposes:
- `resolve()`, `resolveByPath()`, `resolveBySubdomain()`, `resolveStrict()`, `resolveAuto()`
- `getDetectionStrategy()`, `extractSubdomain()`, `matchPathPrefix()`

## Authentication and verification

- `Ronu\AppContext\Auth\Authenticators\JwtAuthenticator`
- `Ronu\AppContext\Auth\Authenticators\ApiKeyAuthenticator`
- `Ronu\AppContext\Auth\Authenticators\AnonymousAuthenticator`
- `Ronu\AppContext\Auth\Verifiers\JwtVerifier`
- `Ronu\AppContext\Auth\Verifiers\ApiKeyVerifier`

These classes are resolved through the service container and used by middleware.

## Repositories

- `ClientRepositoryInterface`
- `ConfigClientRepository`
- `EloquentClientRepository`

## Traits and helpers

- `Traits\HasAppContext` (controller helpers)
- `Traits\ContextualScopes` (Eloquent query scopes and auto-fill)
- `Helpers\HelpersRouting` (module route loading)

## Resources

- `Resources\ContextAwareResource` (channel-aware API resources)

## Evidence
- File: src/Facades/AppContext.php
  - Symbol: AppContext::current(), AppContext::getFacadeAccessor()
  - Notes: Facade entrypoint for the current context.
- File: src/Context/AppContext.php
  - Symbol: AppContext::fromChannel(), AppContext::fromJwt(), AppContext::fromApiKey(), AppContext::requires()
  - Notes: Core context factories and authorization helpers.
- File: src/Context/ContextResolver.php
  - Symbol: ContextResolver::resolve(), ContextResolver::resolveAuto(), ContextResolver::extractSubdomain()
  - Notes: Core channel detection logic.
- File: src/Auth/Authenticators/JwtAuthenticator.php
  - Symbol: JwtAuthenticator::authenticate()
  - Notes: JWT authentication entrypoint.
- File: src/Auth/Verifiers/ApiKeyVerifier.php
  - Symbol: ApiKeyVerifier::verify()
  - Notes: API key verification and metadata extraction.
- File: src/Repositories/ConfigClientRepository.php
  - Symbol: ConfigClientRepository::findByAppCode()
  - Notes: Config-backed repository implementation.
- File: src/Traits/ContextualScopes.php
  - Symbol: ContextualScopes::scopeForContext()
  - Notes: Context-aware model scopes.
- File: src/Resources/ContextAwareResource.php
  - Symbol: ContextAwareResource::toArray()
  - Notes: Resource output varies by channel.
