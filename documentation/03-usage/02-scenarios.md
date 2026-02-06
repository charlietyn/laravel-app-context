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

## Scenario 4: Public ecommerce channel with optional auth + secure endpoints

**Goal**
- Keep most storefront routes public (`catalog`, `search`, `home`) while enforcing JWT on a small set of sensitive endpoints (`checkout`, `orders`, `profile`).

**How the flow works (important)**
For the standard pipeline:
`ResolveAppContext -> RateLimitByContext -> AuthenticateChannel -> EnforceContextBinding -> InjectAuditContext`

- `AuthenticateChannel` runs, but in `jwt_or_anonymous` it can return anonymous context by design.
- If a route later requires `app.scope:*`, anonymous requests usually fail with **Missing Required Permission (403)**, not **Authentication required (401)**.
- `EnforceContextBinding` validates audience/tenant consistency, but does not force login by itself.

**Setup**
- Configure `site.auth_mode = jwt_or_anonymous`.
- Keep public-safe scopes in `public_scopes`.
- Apply `app.auth.required:jwt` only to sensitive route groups.

**Example code**
```php
Route::middleware(['app-context'])->group(function () {
    // Public routes (anonymous allowed)
    Route::get('/site/products', fn () => ['ok' => true]);
    Route::get('/site/search', fn () => ['ok' => true]);

    // Sensitive routes (JWT required)
    Route::middleware(['app.auth.required:jwt', 'app.scope:users:write'])->group(function () {
        Route::post('/site/checkout', fn () => ['ok' => true]);
        Route::get('/site/orders', fn () => ['ok' => true]);
    });
});
```

**Notes**
- This pattern avoids maintaining huge `public_routes` lists in large ecommerce apps.
- If `anonymous_on_invalid_token` is true, invalid tokens can still fallback to anonymous on optional routes.

**Common mistakes**
- Expecting `app.auth` alone to force authentication on `jwt_or_anonymous` channels.
- Using only `app.binding` for auth enforcement (binding != auth requirement).

---

## Scenario 5: “Why am I getting Missing Required Permission instead of 401?”

**Symptom**
- Request without token to a route that has `app.scope:...` returns 403 `Missing Required Permission`.

**Root cause**
- Channel is optional auth (`jwt_or_anonymous`) and request is treated as anonymous.
- Scope middleware then denies missing permission.

**Fix options**
1. Add `app.auth.required:jwt` to that route/group (recommended for selective private endpoints).
2. Move the channel to strict `jwt` if the whole channel should always require token.
3. Fine-tune `public_routes`/`allow_anonymous` behavior based on channel design.

---

## Scenario 6: Do I need `auth:app-context` guard?

**Short answer**
- If you use `app.auth.required` (or your alias like `ctx.auth.required`): **No guard needed**.
- If you use Laravel middleware `auth:app-context`: **Guard config is required**.

**Recommended for juniors (simple setup)**
Use only package middleware:
- `app-context`
- `app.auth.required:jwt` on private groups
- `app.scope:*` for permissions

This avoids extra guard setup while keeping behavior explicit.

**When guard is needed**
Only when you intentionally want to use `auth:app-context`.
Then add:
```php
'guards' => [
    'app-context' => [
        'driver' => 'app-context',
        'provider' => 'users',
    ],
],
```

---

## Scenario 7: Multi-tenant partner integration

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
