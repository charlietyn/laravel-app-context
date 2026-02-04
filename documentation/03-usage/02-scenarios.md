# Scenarios

## Scenario 1: Mobile app with JWT scopes

**Goal**
- Authenticate mobile app requests using JWT and enforce mobile-specific scopes.

**Setup**
- Configure a `mobile` channel with `auth_mode: jwt` and `allowed_scopes`.
- Use the `app-context` middleware group on `/mobile/*` routes.

**Steps**
1. Configure the channel in `config/app-context.php`.
2. Issue JWTs with `aud=mobile` and desired scopes.
3. Apply middleware to mobile routes.

**Example code**
```php
Route::middleware(['app-context', 'app.requires:mobile:orders:read'])->group(function () {
    Route::get('/mobile/orders', fn () => ['ok' => true]);
});
```

**Notes**
- The JWT authenticator builds scopes from JWT claims or user permissions.
- Audience binding ensures tokens cannot be reused across channels.

**Common mistakes**
- Missing `aud` claim when `verify_aud` is enabled.
- Using scopes that are not in `allowed_scopes` for the channel.

---

## Scenario 2: Admin dashboard with subdomain detection

**Goal**
- Route `admin.example.com` requests to the `admin` channel and enforce admin scopes.

**Setup**
- Set `domain` to `example.com`.
- Use `detection_strategy: subdomain` or `auto`.
- Configure the `admin` channel with `subdomains: ['admin']`.

**Steps**
1. Update `config/app-context.php` domain and channel settings.
2. Ensure `admin` routes use the middleware group.
3. Issue tokens with `aud=admin`.

**Example code**
```php
Route::middleware(['app-context', 'app.scope:admin:*'])->group(function () {
    Route::get('/api/admin/metrics', fn () => ['ok' => true]);
});
```

**Notes**
- `EnforceContextBinding` validates JWT audience.
- Admin traffic can be rate-limited independently.

**Common mistakes**
- Misconfigured `domain` causing subdomain extraction to fail.
- Using `path` detection but only subdomains in config.

---

## Scenario 3: Partner API with API keys (config repository)

**Goal**
- Authenticate partner API calls using API keys stored in configuration.

**Setup**
- Use `client_repository.driver=config`.
- Add partner clients under `client_repository.config.clients`.
- Configure a `partner` channel with `auth_mode: api_key`.

**Steps**
1. Add a client definition with `key_hash`, `channel`, and capabilities.
2. Require API key headers in partner routes.

**Example code**
```php
Route::middleware(['app-context', 'app.requires:partner:orders:read'])->group(function () {
    Route::get('/partner/orders', fn () => ['ok' => true]);
});
```

**Notes**
- API keys must be hashed using the configured algorithm.
- Capabilities are filtered by `allowed_capabilities` in the channel.

**Common mistakes**
- Storing a plain key hash when the repository expects bcrypt/argon2id.
- Missing `X-Client-Id` or `X-Api-Key` headers.

---

## Scenario 4: Public site with optional auth

**Goal**
- Allow anonymous access on public routes while accepting JWTs when present.

**Setup**
- Configure `auth_mode: jwt_or_anonymous`.
- Set `public_scopes` to allow safe read-only scopes.

**Steps**
1. Update the `site` channel to `jwt_or_anonymous`.
2. Set `public_routes` or `features.allow_anonymous`.
3. Apply the middleware group to public routes.

**Example code**
```php
Route::middleware(['app-context'])->group(function () {
    Route::get('/site/catalog', fn () => ['ok' => true]);
});
```

**Notes**
- If `anonymous_on_invalid_token` is true, invalid JWTs can fall back to anonymous.

**Common mistakes**
- Leaving `public_scopes` empty and expecting scopes to be granted.
- Forcing JWT auth on routes intended to be public.

---

## Scenario 5: Multi-tenant partner integration

**Goal**
- Enforce tenant binding for partner API keys.

**Setup**
- Set `security.enforce_tenant_binding` to true.
- Configure `tenant_mode: multi` for the channel.
- Include tenant ID in requests (route param, header, or query).

**Steps**
1. Update `config/app-context.php` for tenant enforcement.
2. Ensure API keys include tenant metadata.
3. Send tenant IDs in requests.

**Example code**
```php
Route::middleware(['app-context'])->group(function () {
    Route::get('/partner/tenants/{tenant_id}/orders', fn () => ['ok' => true]);
});
```

**Notes**
- `EnforceContextBinding` checks that the request tenant matches the context tenant.

**Common mistakes**
- Missing tenant ID in route, header, or query when `tenant_mode` is `multi`.

## Evidence
- File: src/Middleware/AuthenticateChannel.php
  - Symbol: AuthenticateChannel::handle()
  - Notes: Authenticates based on the channel's `auth_mode`.
- File: src/Middleware/EnforceContextBinding.php
  - Symbol: EnforceContextBinding::handle(), EnforceContextBinding::validateTenantBinding()
  - Notes: Enforces audience and tenant binding rules.
- File: src/Auth/Authenticators/JwtAuthenticator.php
  - Symbol: JwtAuthenticator::buildScopes(), JwtAuthenticator::shouldFallbackOnInvalidToken()
  - Notes: Builds scopes and supports optional JWT auth.
- File: src/Auth/Authenticators/ApiKeyAuthenticator.php
  - Symbol: ApiKeyAuthenticator::authenticate(), ApiKeyAuthenticator::buildCapabilities()
  - Notes: Builds capabilities for API key channels.
- File: src/Repositories/ConfigClientRepository.php
  - Symbol: ConfigClientRepository::findByAppCode(), ConfigClientRepository::verifyKeyHash()
  - Notes: Validates API keys from config repository.
