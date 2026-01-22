# Repo Findings Summary

- Package name: `ronu/laravel-app-context` with Laravel 11/12 support and JWT via `php-open-source-saver/jwt-auth`. The service provider is `Ronu\AppContext\AppContextServiceProvider`.
- Middleware provided: `app.context`, `app.auth`, `app.binding`, `app.scope`, `app.throttle`, `app.audit`, plus the `app-context` group.
- Configuration lives in `config/app-context.php` (channels, client repository, JWT, API keys, rate limiting, security, audit, public routes).
- Storage: config-based clients or database-backed repositories (legacy `api_clients` or recommended `api_apps` + `api_app_keys`).
- JWT verification includes strict algorithm checks and audience/issuer validation; API key verification uses headers `X-Client-Id` and `X-Api-Key` by default.

# Documentation

## 1) Title + One-paragraph Overview

**Laravel App Context – Multi-Channel Context + JWT/API Key Security**

This package provides deterministic application context resolution (channel + tenant + auth mode), standardized middleware ordering, JWT/API key authentication integration, and context-aware rate limiting/logging for Laravel 11/12 applications. It resolves context from host/path only (never from unsigned headers), binds tokens to channel and tenant, and exposes a single `AppContext` object for authorization decisions. All registration is done via `Ronu\AppContext\AppContextServiceProvider`, with configuration in `config/app-context.php`.

## 2) Quick Start (5–10 steps)

1) Install the package with Composer (see Installation).
2) Publish the config: `php artisan vendor:publish --tag=app-context-config`.
3) Configure `config/app-context.php` channels (e.g., `mobile`, `admin`, `partner`) and select `auth_mode` per channel.
4) Choose a client repository driver (`config` or `eloquent`).
5) If using `eloquent`, add tables for `api_apps` + `api_app_keys` (or legacy `api_clients`).
6) Add middleware to route groups in the correct order (see Middleware Reference + Channel Setup Examples).
7) Ensure login routes only run `app.context` + rate limiting, then issue JWT with `aud` matching the channel.
8) Ensure `app.binding` runs after JWT to enforce audience/tenant binding.
9) Validate API key headers (`X-Client-Id`, `X-Api-Key`) for B2B routes.
10) Verify rate limit profiles and audit logging settings in `config/app-context.php`.

## 3) Installation

### Composer

```bash
composer require ronu/laravel-app-context
```

### Publish configuration

```bash
php artisan vendor:publish --tag=app-context-config
```

### Service Provider Auto-Discovery

Laravel auto-discovers the service provider via `composer.json`. If auto-discovery is disabled, register it in your app’s provider list:

```php
// config/app.php
'providers' => [
    Ronu\AppContext\AppContextServiceProvider::class,
],
```

## 4) Package Architecture (include a Mermaid diagram of request flow)

**Request Flow Overview**

```mermaid
flowchart TD
    A[Incoming Request] --> B[ResolveAppContext (host/path)]
    B --> C{Auth Mode}
    C -->|jwt| D[AuthenticateChannel: JWT]
    C -->|api_key| E[AuthenticateChannel: API Key]
    C -->|anonymous| F[AuthenticateChannel: Anonymous]
    D --> G[EnforceContextBinding]
    E --> G[EnforceContextBinding]
    F --> G[EnforceContextBinding]
    G --> H[RateLimitByContext]
    H --> I[InjectAuditContext]
    I --> J[RequireScope (per-route)]
    J --> K[Controller / App Logic]
```

## 5) Middleware Reference

> All middleware aliases and the `app-context` group are registered in `Ronu\AppContext\AppContextServiceProvider` via `Router::aliasMiddleware()` and `middlewareGroup()`.

| Middleware | Purpose | Where to register | Order | Applies to |
|---|---|---|---|---|
| `app.context` | Resolve channel + base context from host/path | Route group (or `app-context` group) | 1 | dashboard, mobile, b2b |
| `app.auth` | Authenticate per channel (`jwt`, `api_key`, `anonymous`) | Route group | 2 | dashboard, mobile, b2b |
| `app.binding` | Enforce audience/tenant binding | Route group | 3 | dashboard, mobile, b2b |
| `app.throttle` | Context-aware rate limiting | Route group | 4 | dashboard, mobile, b2b |
| `app.audit` | Inject context into logs | Route group | 5 | dashboard, mobile, b2b |
| `app.scope` | Enforce scopes/capabilities (OR) | Per-route | After auth/binding | dashboard, mobile, b2b |

**Note:** There is an additional middleware class `Ronu\AppContext\Middleware\RequireAllScopes`, but it is not aliased by the service provider. If you want to use it, register an alias in your app (see below).

### Optional: Register `RequireAllScopes` alias (if you want AND logic)

**Laravel 11/12 (`bootstrap/app.php`)**

```php
// bootstrap/app.php
->withMiddleware(function (Illuminate\Foundation\Configuration\Middleware $middleware) {
    $middleware->alias([
        'app.scope.all' => Ronu\AppContext\Middleware\RequireAllScopes::class,
    ]);
})
```

**Legacy (`app/Http/Kernel.php`)**

```php
// app/Http/Kernel.php
protected $routeMiddleware = [
    'app.scope.all' => Ronu\AppContext\Middleware\RequireAllScopes::class,
];
```

## 6) Configuration

Configuration file: `config/app-context.php`.

### Core Keys

| Key | Description | Default / Example |
|---|---|---|
| `client_repository.driver` | Storage backend (`config`, `eloquent`, or custom class) | `config` |
| `deny_by_default` | Reject requests with no channel match | `true` |
| `default_channel` | Channel used when deny-by-default is off | `default` |
| `domain` | Base domain for subdomain parsing | `APP_CONTEXT_DOMAIN` |
| `detection_strategy` | `auto`, `path`, `subdomain`, `strict` | `auto` |
| `auto_detection_rules` | Host → strategy mapping | see file |
| `app_context_dev` | Envs that default to path detection | `local` |
| `channels` | Channel definitions (auth mode, scopes, capabilities) | see file |
| `rate_limits` | Channel rate limit profiles | see file |
| `jwt` | JWT verification + fallback settings | see file |
| `api_key` | API key headers, rotation, format | see file |
| `security` | Enforcement toggles | see file |
| `audit` | Logging configuration | see file |
| `public_routes` | Paths/names that skip auth | see file |

### Channel Definitions (critical for security)

Each channel in `config/app-context.php` defines:
- **`auth_mode`**: `jwt`, `api_key`, `anonymous`, or `jwt_or_anonymous`.
- **`jwt_audience`**: expected `aud` for JWT channels.
- **`allowed_scopes`** / **`allowed_capabilities`**: allow-list for JWT/API key permissions.
- **`tenant_mode`**: `single` or `multi`.

### API Key Headers

Default headers (configurable in `api_key.headers`):
- `X-Client-Id` → client identifier (`app_code`)
- `X-Api-Key` → API key (format: `prefix.secret`)

### Secure Defaults

Recommended production defaults already reflected in the config:
- `deny_by_default = true`
- `security.strict_algorithm_check = true`
- `jwt.verify_aud = true` and `jwt.verify_iss = true`
- `api_key.hash_algorithm = argon2id`
- `security.enforce_tenant_binding = true`

## 7) Authentication (JWT with php-open-source-saver/jwt-auth)

### Controller changes (login/logout/refresh)

> The package **does not** ship an AuthController. If your app already has `AuthController@login`, `logout`, and `refresh`, keep them and add app-context binding and claims as shown below.

**Where to put:** Your application’s `app/Http/Controllers/AuthController.php`.

#### Login (JWT: bind app context into claims)

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Ronu\AppContext\Context\AppContext;

public function login(Request $request, AppContext $context)
{
    $credentials = $request->only(['email', 'password']);

    if (! $token = Auth::attempt($credentials)) {
        return response()->json(['message' => 'Invalid credentials'], 401);
    }

    // Bind app context to JWT claims
    $claims = [
        'aud' => $context->getAppId(),
        'tid' => $request->header('X-Tenant-Id') ?? $request->route('tenant_id') ?? $request->query('tenant_id'),
        'scp' => [],
    ];

    $token = JWTAuth::claims($claims)->fromUser(Auth::user());

    return response()->json([
        'access_token' => $token,
        'token_type' => 'Bearer',
        'expires_in' => config('app-context.jwt.ttl'),
        'audience' => $context->getAppId(),
        'tenant_id' => $claims['tid'],
    ]);
}
```

#### Logout (invalidate current token)

```php
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

public function logout()
{
    JWTAuth::invalidate(JWTAuth::getToken());

    return response()->json(['message' => 'Logged out']);
}
```

#### Refresh (refresh token, preserve claims)

```php
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

public function refresh()
{
    $newToken = JWTAuth::refresh(JWTAuth::getToken());

    return response()->json([
        'access_token' => $newToken,
        'token_type' => 'Bearer',
        'expires_in' => config('app-context.jwt.ttl'),
    ]);
}
```

### Route examples

**Login route group** (no `app.auth`):

```php
// routes/api.php
Route::middleware([
    'app.context',
    'app.binding',
    'app.throttle',
    'app.audit',
])->post('/api/login', [AuthController::class, 'login']);
```

**Authenticated route group**:

```php
Route::middleware([
    'app.context',
    'app.auth',
    'app.binding',
    'app.throttle',
    'app.audit',
])->group(function () {
    Route::get('/api/me', [AuthController::class, 'me']);
});
```

### Token claims binding to app_context (recommended)

Use at least these claims in JWTs:
- `aud`: channel id (e.g., `admin`, `mobile`, `site`)
- `tid`: tenant id (if multi-tenant)
- `scp`: scopes list (if your app manages scopes)

`app.binding` enforces `aud` (if enabled) and compares tenant ID (`tid`) with request tenant data.

## 8) Channel Setup Examples

### dashboard (web client / SPA)

**Expected channel**: `admin` (JWT)

```php
// routes/api.php
Route::prefix('api')->middleware([
    'app.context',
    'app.auth',
    'app.binding',
    'app.throttle',
    'app.audit',
])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index'])
        ->middleware('app.scope:admin:dashboard:read');
});
```

### mobile

**Expected channel**: `mobile` (JWT)

```php
// routes/api.php
Route::prefix('mobile')->middleware([
    'app.context',
    'app.auth',
    'app.binding',
    'app.throttle',
    'app.audit',
])->group(function () {
    Route::get('/orders', [OrderController::class, 'index'])
        ->middleware('app.scope:mobile:orders:read');
});
```

### b2b APIs

**Expected channel**: `partner` (API key)

```php
// routes/api.php
Route::prefix('partner')->middleware([
    'app.context',
    'app.auth',
    'app.binding',
    'app.throttle',
    'app.audit',
])->group(function () {
    Route::get('/inventory', [PartnerInventoryController::class, 'index'])
        ->middleware('app.scope:partner:inventory:read');
});
```

## 9) Troubleshooting

- **“AppContext not resolved”** → Ensure `app.context` is first in the middleware chain.
- **JWT audience mismatch** → Ensure login issues tokens with `aud` matching channel (`admin`, `mobile`, etc.).
- **Tenant mismatch errors** → Confirm tenant id is provided in route param `tenant_id`/`tenantId`, header `X-Tenant-Id`, or query `tenant_id`.
- **API key not accepted** → Verify `X-Client-Id` + `X-Api-Key` headers and ensure the key hash matches.

## 10) Security Checklist

- [ ] `deny_by_default = true` in production.
- [ ] `jwt.verify_aud = true` and `jwt.verify_iss = true`.
- [ ] Tokens include `aud` (channel) and `tid` (tenant).
- [ ] API keys stored with Argon2id/Bcrypt hashes (never plaintext).
- [ ] IP allowlists enforced for high-risk partners (`security.enforce_ip_allowlist`).
- [ ] Audit logging enabled for authentication failures.
- [ ] Rate limits configured per channel and endpoint.

## 11) Changelog Notes (breaking changes / upgrade tips)

N/A (no changelog files found in the repository).
