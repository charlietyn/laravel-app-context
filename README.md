# Laravel App Context

[![Latest Version on Packagist](https://img.shields.io/packagist/v/ronu/laravel-app-context.svg?style=flat-square)](https://packagist.org/packages/ronu/laravel-app-context)
[![Total Downloads](https://img.shields.io/packagist/dt/ronu/laravel-app-context.svg?style=flat-square)](https://packagist.org/packages/ronu/laravel-app-context)
[![License](https://img.shields.io/packagist/l/ronu/laravel-app-context.svg?style=flat-square)](https://packagist.org/packages/ronu/laravel-app-context)

Multi-channel application context management for Laravel with JWT and API Key authentication.

> Spanish documentation: [README.es.md](README.es.md)

## Features

- 🔐 **Multi-Auth Support**: JWT, API Key, and Anonymous authentication
- 🎯 **Channel-Based Routing**: Auto-detect channels from subdomain or path
- 🛡️ **Security First**: Algorithm confusion prevention, blacklist, tenant binding
- 📊 **Rate Limiting**: Context-aware rate limiting per channel
- 📝 **Audit Logging**: Automatic context injection into all logs
- 🔑 **Scope/Capability System**: Wildcard support for permissions

## Requirements

- PHP 8.2+
- Laravel 11.0+ or 12.0+
- php-open-source-saver/jwt-auth 2.0+

## Installation

```bash
composer require ronu/laravel-app-context
```

Publish the configuration:

```bash
php artisan vendor:publish --tag=app-context-config
```

Publish and run migrations:

```bash
php artisan vendor:publish --tag=app-context-migrations
php artisan migrate
```

## Quick Start

### 1. Configure Channels

Edit `config/app-context.php` to define your channels:

```php
'channels' => [
    'mobile' => [
        'subdomains' => ['mobile', 'm'],
        'path_prefixes' => ['/mobile'],
        'auth_mode' => 'jwt',
        'jwt_audience' => 'mobile',
        'allowed_scopes' => ['mobile:*', 'user:profile:*'],
    ],
    
    'admin' => [
        'subdomains' => ['admin'],
        'path_prefixes' => ['/api'],
        'auth_mode' => 'jwt',
        'jwt_audience' => 'admin',
        'allowed_scopes' => ['admin:*'],
    ],
    
    'partner' => [
        'subdomains' => ['api-partners'],
        'path_prefixes' => ['/partner'],
        'auth_mode' => 'api_key',
        'allowed_capabilities' => ['partner:*'],
    ],
],
```

### 2. Apply Middleware

Add the middleware group to your routes:

```php
// routes/api.php
Route::middleware(['app-context'])->group(function () {
    Route::get('/users', [UserController::class, 'index']);
});

// Or use individual middleware
Route::middleware([
    'app.context',      // Resolve context
    'app.auth',         // Authenticate
    'app.binding',      // Enforce bindings
    'app.throttle',     // Rate limit
    'app.audit',        // Audit logging
])->group(function () {
    // ...
});
```

### 3. Require Scopes

```php
Route::middleware(['app.scope:admin:users:read'])
    ->get('/api/users', [UserController::class, 'index']);

Route::middleware(['app.scope:admin:users:write,admin:users:delete'])
    ->delete('/api/users/{id}', [UserController::class, 'destroy']);
```

## Usage

### Accessing AppContext

```php
use Ronu\AppContext\Facades\AppContext;

// Get current context
$context = AppContext::current();

// Check authentication
if ($context->isAuthenticated()) {
    $userId = $context->getUserId();
}

// Check permissions
if ($context->hasScope('admin:users:read')) {
    // ...
}

// Require permission (throws exception if missing)
$context->requires('admin:export:run');
```

### In Controllers

```php
use Ronu\AppContext\Context\AppContext;

class UserController extends Controller
{
    public function index(AppContext $context)
    {
        // Context is injected via DI
        $context->requires('admin:users:read');
        
        return User::query()
            ->when($context->getTenantId(), fn($q, $tid) => $q->where('tenant_id', $tid))
            ->get();
    }
}
```

### API Key Management

```bash
# Generate a new API key
php artisan app-context:generate-key "Partner Company" \
    --channel=partner \
    --capabilities=partner:orders:create \
    --capabilities=partner:inventory:read

# List all clients
php artisan app-context:list-clients

# Revoke a key
php artisan app-context:revoke-key partner-company_abc123
```

## Middleware Pipeline

The recommended middleware order:

```
1. ResolveAppContext    → Detect channel from host/path
2. AuthenticateChannel  → JWT/API Key authentication
3. EnforceContextBinding→ Validate audience/tenant
4. RateLimitByContext   → Apply rate limits
5. InjectAuditContext   → Inject context into logs
6. RequireScope         → Check permissions (per-route)
```

## Security Features

### Algorithm Confusion Prevention

The JWT verifier explicitly rejects the `none` algorithm (CVE-2015-9235):

```php
// config/app-context.php
'jwt' => [
    'allowed_algorithms' => ['HS256', 'RS256', 'RS384', 'RS512'],
    // NEVER include 'none' here
],
```

### Audience Claim Enforcement

When `JWT_VERIFY_AUD=true` (default), tokens must include an `aud` claim.
Channel binding is enforced by middleware to ensure the token audience matches the resolved channel.

### Audience Binding

Tokens are bound to their intended channel:

- Token with `aud=mobile` cannot access `/api/*` (admin channel)
- Token with `aud=admin` cannot access `/mobile/*`

### Tenant Binding

Multi-tenant isolation prevents cross-tenant access:

- Token with `tid=tenant_1` cannot access resources of `tenant_2`

### API Key Security

- Argon2id hashing (recommended) or Bcrypt
- IP allowlist with CIDR support
- Optional global enforcement of IP allowlists (`APP_CONTEXT_IP_ALLOWLIST=true`)
- Automatic expiration
- Usage tracking

## Advanced Review (Improvements & Defects)

### Recommended improvements (security/operations)

- **Deny-by-default and strict detection in sensitive environments**: enable `APP_CONTEXT_DENY_BY_DEFAULT=true` and consider `APP_CONTEXT_DETECTION=strict` to require subdomain + path alignment, reducing ambiguous routing bypasses.【F:config/app-context.php†L16-L63】
- **Harden JWT for production**: use RS256 with dedicated keys, keep `verify_iss`/`verify_aud` enabled, and disable the dev fallback (`JWT_DEV_FALLBACK=false`).【F:config/app-context.php†L284-L330】
- **Safe auditing defaults**: keep `include_request_body=false` and rely on `sensitive_headers` redaction to avoid leaking secrets; enable audit logging only with a secure log pipeline.【F:config/app-context.php†L390-L429】
- **Trusted proxies for IP allowlists**: if you enforce IP allowlists for API keys, ensure Laravel `TrustProxies` is configured because the package uses `Request::ip()` directly.【F:src/Auth/Verifiers/ApiKeyVerifier.php†L101-L108】

### Known defects/limitations

- **IP allowlist is IPv4-only**: CIDR validation relies on `ip2long`, so IPv6 ranges are not handled correctly.【F:src/Auth/Verifiers/ApiKeyVerifier.php†L214-L228】
- **`rate_limit_profile` is unused**: channels define `rate_limit_profile`, but the middleware selects limits by channel ID (`app-context.rate_limits.{channel}`), so the parameter has no effect today.【F:config/app-context.php†L80-L161】【F:src/Middleware/RateLimitByContext.php†L73-L92】
- **Non-atomic `usage_count` updates**: API key usage increments use `usage_count + 1` in an `afterResponse` dispatch, which can drop increments under high concurrency.【F:src/Auth/Verifiers/ApiKeyVerifier.php†L233-L246】

### Remediation plan (prioritized)

1. **Rate limiting correctness**
   - Wire `rate_limit_profile` and optional `rate_limit_tier` to actual limiter selection (avoid hardcoding to channel ID).【F:config/app-context.php†L80-L205】【F:src/Middleware/RateLimitByContext.php†L73-L122】
   - Implement or remove `burst` to avoid a misleading configuration surface.【F:config/app-context.php†L167-L245】【F:src/Middleware/RateLimitByContext.php†L73-L122】
2. **API key safety and telemetry**
   - Replace non-atomic `usage_count + 1` with a DB atomic increment (and consider a queue).【F:src/Auth/Verifiers/ApiKeyVerifier.php†L233-L246】
   - Add IPv6 support to CIDR checks (e.g., `inet_pton`) or document IPv4-only constraints clearly.【F:src/Auth/Verifiers/ApiKeyVerifier.php†L214-L228】
3. **JWT operational hardening**
   - Consider disabling query/cookie token parsing in production to reduce token leakage risk (prefer Authorization header only).【F:src/Auth/Verifiers/JwtVerifier.php†L150-L175】
4. **Anonymous/default context clarity**
   - Define an explicit `default` channel or enforce `deny_by_default` in production to avoid implicit behavior for unmapped routes.【F:src/Middleware/ResolveAppContext.php†L44-L66】

## Configuration

### Environment Variables

```env
# Core
APP_CONTEXT_DOMAIN=myapp.com
APP_CONTEXT_DETECTION=auto
APP_CONTEXT_DENY_BY_DEFAULT=true

# JWT
JWT_ALGO=RS256
JWT_ISSUER=https://myapp.com
JWT_TTL=3600
JWT_BLACKLIST_ENABLED=true
JWT_DEV_FALLBACK=true
JWT_DEV_ALGO=HS256
JWT_DEV_SECRET=base64:your-app-key

# API Key
API_KEY_HASH_ALGO=argon2id
API_KEY_ROTATION_DAYS=90
APP_CONTEXT_IP_ALLOWLIST=false

# Rate Limiting
RATE_LIMIT_MOBILE_GLOBAL=60/m
RATE_LIMIT_ADMIN_GLOBAL=120/m
RATE_LIMIT_PARTNER_GLOBAL=600/m
```

### Development Fallback for JWT Keys

In local/staging environments, if RSA key files are missing and `JWT_DEV_FALLBACK=true`,
the package falls back to symmetric signing (default `HS256`) using `JWT_DEV_SECRET`,
`APP_KEY`, or a `dev-secret` fallback. This avoids blocking development setups that don't
have key files yet.

> **Recommendation:** Use RSA keys in production and disable the fallback there.

## Testing

```bash
composer test
```

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
