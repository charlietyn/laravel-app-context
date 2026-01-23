# Laravel App Context

[![Latest Version on Packagist](https://img.shields.io/packagist/v/ronu/laravel-app-context.svg?style=flat-square)](https://packagist.org/packages/ronu/laravel-app-context)
[![Total Downloads](https://img.shields.io/packagist/dt/ronu/laravel-app-context.svg?style=flat-square)](https://packagist.org/packages/ronu/laravel-app-context)
[![License](https://img.shields.io/packagist/l/ronu/laravel-app-context.svg?style=flat-square)](https://packagist.org/packages/ronu/laravel-app-context)

Multi-channel application context management for Laravel with JWT and API Key authentication.

> Spanish documentation: [README.es.md](README.es.md)

## Features

- **Multi-Auth Support**: JWT, API Key, and Anonymous authentication
- **Channel-Based Routing**: Auto-detect channels from subdomain or path
- **Security First**: Algorithm confusion prevention, blacklist, tenant binding
- **Rate Limiting**: Context-aware rate limiting per channel
- **Audit Logging**: Automatic context injection into all logs
- **Scope/Capability System**: Wildcard support for permissions
- **Flexible Client Storage**: Config-based (no database), Eloquent, or custom repositories

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

**Optional** - If you use the `eloquent` driver, create the database tables in your application
(migration example included below).

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

    'site' => [
        'subdomains' => ['www', null],
        'path_prefixes' => ['/site'],
        'auth_mode' => 'jwt_or_anonymous',
        'allowed_scopes' => ['site:*', 'catalog:browse', 'public:read'],
        'public_scopes' => ['catalog:browse', 'public:read'],
        'anonymous_on_invalid_token' => false,
        'audit' => [
            'enabled' => false,
        ],
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
    'app.throttle',     // Rate limit
    'app.auth',         // Authenticate
    'app.binding',      // Enforce bindings
    'app.requires',     // Require scopes/capabilities (per-route)
    'app.audit',        // Audit logging
])->group(function () {
    // ...
});
```

### 3. Require Abilities (recommended)

```php
Route::middleware(['app.requires:admin:users:read'])
    ->get('/api/users', [UserController::class, 'index']);

Route::middleware(['app.requires:admin:users:write,admin:users:delete'])
    ->delete('/api/users/{id}', [UserController::class, 'destroy']);

Route::middleware(['app.requires.all:admin:users:read,admin:users:write'])
    ->put('/api/users/{id}', [UserController::class, 'update']);
```

Legacy aliases remain available:

```php
Route::middleware(['app.scope:admin:users:read'])
    ->get('/api/users', [UserController::class, 'index']);
```

---

## Middleware Integration Guide

The package ships with granular middleware so you can compose a secure pipeline per route group:

| Middleware | Responsibility |
|------------|----------------|
| `app.context` | Resolve channel + context |
| `app.auth` | Authenticate (JWT, API Key, or anonymous) |
| `app.binding` | Enforce channel/tenant binding |
| `app.scope` | Enforce scopes/capabilities (legacy) |
| `app.requires` | Enforce scopes/capabilities (recommended) |
| `app.throttle` | Context-aware rate limiting |
| `app.audit` | Inject context into logs |

**Recommended order (most routes):**

```php
Route::middleware([
    'app.context',
    'app.throttle',
    'app.auth',
    'app.binding',
    'app.requires',
    'app.audit',
])->group(function () {
    // Protected routes
});
```

**Login endpoints (JWT):** resolve context and apply rate limiting **without** `app.auth`, then issue the token in your controller.

```php
Route::middleware([
    'app.context',
    'app.throttle',
    'app.binding',
    'app.audit',
])->post('/api/login', [AuthController::class, 'login']);
```

**API Key endpoints:** there is no login route. The API key is sent on every request and validated by `app.auth`.

**Avoid double rate limiting:** if you enable `app.throttle` (`RateLimitByContext`) in your API group, remove Laravel's default `throttle:api` middleware (or set it to a very high limit) to prevent double throttling.

---

## Login Flow with `api_apps` + `api_app_keys`

When you adopt the two-table schema, **`api_apps` is the client registry** and **`api_app_keys` stores the keys per client**:

1. **Create an app** in `api_apps` with `app_code`, `app_name`, `is_active = true`.
2. **Create one or more keys** in `api_app_keys` for that app.
3. Clients authenticate by sending:
   - `X-Client-Id: <app_code>`
   - `X-Api-Key: <prefix>.<secret>`

**JWT login (user-based):**
- The login route only needs the channel context (`app.context`) and normal Laravel auth.
- The resulting JWT should include the audience (`aud`) that matches the channel configuration.

**API Key login (machine-to-machine):**
- There is **no login**. Each request uses the API key; the library validates:
  - `api_apps.is_active`
  - `api_app_keys.revoked_at` + `expires_at`
  - `api_app_keys.scopes` or `api_app_keys.config.capabilities`

---

## Client Repository Configuration

The library uses a **repository pattern** for API client storage, allowing you to choose between different storage backends without modifying core code.

### Available Drivers

| Driver | Database Required | Use Case |
|--------|-------------------|----------|
| `config` | No | Simple setups, few partners, stateless deployments |
| `eloquent` | Yes | Dynamic client management, many partners |
| Custom class | Depends | Redis, external API, custom storage |

### Configuration Structure

```php
// config/app-context.php
'client_repository' => [
    // Driver selection: 'config', 'eloquent', or fully qualified class name
    'driver' => env('APP_CONTEXT_CLIENT_DRIVER', 'config'),

    // Settings for 'config' driver
    'config' => [
        'hash_algorithm' => env('API_KEY_HASH_ALGO', 'bcrypt'),
        'prefix_length' => 10,
        'key_length' => 32,
        'clients' => [
            // Client definitions here
        ],
    ],

    // Settings for 'eloquent' driver
    'eloquent' => [
        // Legacy single-table schema
        'table' => env('APP_CONTEXT_CLIENTS_TABLE', 'api_clients'),
        // Multi-table schema (recommended)
        'apps_table' => env('APP_CONTEXT_APPS_TABLE', 'api_apps'),
        'app_keys_table' => env('APP_CONTEXT_APP_KEYS_TABLE', 'api_app_keys'),
        // Optional: pass model classes for apps/keys
        'app_model' => env('APP_CONTEXT_APP_MODEL'),
        'app_key_model' => env('APP_CONTEXT_APP_KEY_MODEL'),
        'connection' => env('APP_CONTEXT_CLIENTS_CONNECTION', null),
        'hash_algorithm' => env('API_KEY_HASH_ALGO', 'argon2id'),
        'async_tracking' => true,
    ],
],
```

---

### Option A: Config Driver (No Database)

The `config` driver allows you to define API clients directly in configuration files. This is ideal for:

- Simple setups with few partners
- Development and testing environments
- Stateless/serverless deployments
- Infrastructure-as-Code approaches

#### Step 1: Generate API Key Hash

```bash
# Using Laravel Tinker
php artisan tinker --execute="echo Hash::make('your-secret-api-key');"

# Output: $2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi
```

#### Step 2: Define Clients in Configuration

```php
// config/app-context.php
'client_repository' => [
    'driver' => 'config',

    'config' => [
        'hash_algorithm' => 'bcrypt', // or 'argon2id'

        'clients' => [
            // Client identifier (used as X-Client-Id header value)
            'acme-corp' => [
                'name' => 'ACME Corporation',
                'key_hash' => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
                'channel' => 'partner',
                'tenant_id' => null, // null = access to all tenants
                'capabilities' => [
                    'partner:orders:*',
                    'partner:inventory:read',
                    'webhooks:receive',
                ],
                'ip_allowlist' => [
                    '203.0.113.0/24',    // CIDR notation supported
                    '198.51.100.42',     // Single IP
                ],
                'is_active' => true,
                'is_revoked' => false,
                'expires_at' => '2025-12-31 23:59:59', // null = never expires
                'metadata' => [
                    'rate_limit_tier' => 'premium',
                    'webhook_url' => 'https://acme.example.com/webhooks',
                ],
            ],

            'beta-partner' => [
                'name' => 'Beta Partner',
                'key_hash' => '$2y$10$...', // Another bcrypt hash
                'channel' => 'partner',
                'capabilities' => ['partner:orders:read'],
                'ip_allowlist' => [],
                'is_active' => true,
            ],
        ],
    ],
],
```

#### Step 3: Use the API Key

```bash
curl -X GET "https://api.example.com/partner/orders" \
  -H "X-Client-Id: acme-corp" \
  -H "X-Api-Key: your-secret-api-key"
```

#### Limitations of Config Driver

- Cannot create/revoke clients at runtime (use `php artisan` helper)
- No usage tracking (last_used_at, usage_count)
- Changes require configuration file updates

---

### Option B: Eloquent Driver (Database)

The `eloquent` driver stores clients in a database table. This is ideal for:

- Dynamic client management
- Large number of partners
- Usage tracking and analytics
- Runtime key generation and revocation

#### Step 1: Set Environment Variable

```env
APP_CONTEXT_CLIENT_DRIVER=eloquent
```

#### Step 2: Create the Apps + Keys Tables (Recommended)

Create migrations for **`api_apps`** (clients) and **`api_app_keys`** (keys per app).
This matches the schema you shared and allows multiple keys per client:

| Table | Column | Description |
|-------|--------|-------------|
| `api_apps` | `app_code` | Unique client identifier (X-Client-Id) |
| `api_apps` | `app_name` | Human-readable client name |
| `api_apps` | `is_active` | Whether the client is active |
| `api_apps` | `config` | JSON with channel, tenant_id, rate limits, etc. |
| `api_app_keys` | `app_id` | FK to `api_apps.id` |
| `api_app_keys` | `key_prefix` | First chars of the key |
| `api_app_keys` | `key_hash` | Argon2id/Bcrypt hash |
| `api_app_keys` | `scopes` | Scope list (text/json) |
| `api_app_keys` | `config` | JSON with capabilities, ip_allowlist, etc. |
| `api_app_keys` | `expires_at` | Expiration date |
| `api_app_keys` | `revoked_at` | Revocation timestamp |
| `api_app_keys` | `last_used_at` | Last usage timestamp |
| `api_app_keys` | `last_used_ip` | Last request IP |
| `api_app_keys` | `last_user_agent` | Last request UA |

**Important:** the `eloquent` driver can also work with the legacy single-table schema (`api_clients`).

#### Step 3: Point the Library to Your Models

Update `config/app-context.php` (or env) so the library knows which models to use:

```php
'client_repository' => [
    'driver' => 'eloquent',
    'eloquent' => [
        'app_model' => \App\Models\ApiApp::class,
        'app_key_model' => \App\Models\ApiAppKey::class,
    ],
],
```

#### Step 3: Generate API Keys via Artisan

```bash
# Generate a new API key
php artisan app-context:generate-key "Partner Company" \
    --channel=partner \
    --tenant=tenant_123 \
    --capabilities=partner:orders:create \
    --capabilities=partner:inventory:read \
    --ip-allowlist=203.0.113.0/24 \
    --expires=2025-12-31

# List all clients
php artisan app-context:list-clients
php artisan app-context:list-clients --channel=partner
php artisan app-context:list-clients --include-revoked

# Revoke a key
php artisan app-context:revoke-key partner-company_abc123
php artisan app-context:revoke-key partner-company_abc123 --force
```

#### Eloquent Configuration Options

```php
'eloquent' => [
    // Legacy single-table name
    'table' => 'my_api_clients',

    // Multi-table names
    'apps_table' => 'security.api_apps',
    'app_keys_table' => 'security.api_app_keys',

    // Optional model classes
    'app_model' => \App\Models\ApiApp::class,
    'app_key_model' => \App\Models\ApiAppKey::class,

    // Use a different database connection
    'connection' => 'mysql_readonly',

    // Hash algorithm (argon2id recommended for production)
    'hash_algorithm' => 'argon2id',

    // Key generation settings
    'prefix_length' => 10,
    'key_length' => 32,

    // Track usage asynchronously (recommended for performance)
    'async_tracking' => true,
],
```

---

### Option C: Custom Repository

You can implement your own storage backend by creating a class that implements `ClientRepositoryInterface`.

#### Step 1: Create Custom Repository

```php
<?php

namespace App\Repositories;

use Ronu\AppContext\Contracts\ClientRepositoryInterface;
use Ronu\AppContext\Support\ClientInfo;
use Illuminate\Support\Facades\Redis;

class RedisClientRepository implements ClientRepositoryInterface
{
    public function __construct(private array $config)
    {
        // Initialize with config from app-context.php
    }

    public function findByAppCode(string $appCode, ?string $keyPrefix = null): ?ClientInfo
    {
        $data = Redis::hgetall("api_apps:{$appCode}");

        if (empty($data)) {
            return null;
        }

        return ClientInfo::fromArray([
            'app_code' => $appCode,
            'name' => $data['name'],
            'key_hash' => $data['key_hash'],
            'channel' => $data['channel'],
            'tenant_id' => $data['tenant_id'] ?? null,
            'capabilities' => json_decode($data['capabilities'] ?? '[]', true),
            'ip_allowlist' => json_decode($data['ip_allowlist'] ?? '[]', true),
            'is_active' => (bool) ($data['is_active'] ?? true),
            'is_revoked' => (bool) ($data['is_revoked'] ?? false),
            'expires_at' => $data['expires_at'] ?? null,
        ]);
    }

    public function verifyKeyHash(string $key, string $storedHash): bool
    {
        return password_verify($key, $storedHash);
    }

    public function trackUsage(
        string $appCode,
        string $ip,
        ?string $keyPrefix = null,
        ?string $userAgent = null
    ): void
    {
        Redis::hincrby("api_apps:{$appCode}", 'usage_count', 1);
        Redis::hset("api_apps:{$appCode}", 'last_used_ip', $ip);
        Redis::hset("api_apps:{$appCode}", 'last_used_at', now()->toIso8601String());
    }

    public function generateKey(): array
    {
        $prefix = \Illuminate\Support\Str::random(10);
        $secret = \Illuminate\Support\Str::random(32);
        $key = "{$prefix}.{$secret}";

        return [
            'key' => $key,
            'hash' => password_hash($key, PASSWORD_ARGON2ID),
            'prefix' => $prefix,
        ];
    }

    public function create(array $data): ClientInfo
    {
        // Implement Redis storage logic
    }

    public function revoke(string $appCode): bool
    {
        return Redis::hset("api_apps:{$appCode}", 'is_revoked', '1') > 0;
    }

    public function all(array $filters = []): iterable
    {
        // Implement listing logic
    }
}
```

#### Step 2: Configure Custom Driver

```php
// config/app-context.php
'client_repository' => [
    'driver' => \App\Repositories\RedisClientRepository::class,

    // Custom configuration passed to repository constructor
    \App\Repositories\RedisClientRepository::class => [
        'prefix' => 'api_apps',
        'connection' => 'default',
    ],
],
```

---

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

// Ability check across scopes/capabilities
if ($context->hasAbility('catalog:browse')) {
    // ...
}
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

### Using HasAppContext Trait

```php
use Ronu\AppContext\Traits\HasAppContext;

class OrderController extends Controller
{
    use HasAppContext;

    public function index()
    {
        // Access context via trait
        if ($this->appContext()->hasCapability('partner:orders:read')) {
            return Order::forTenant($this->appContext()->getTenantId())->get();
        }
    }
}
```

---

## Middleware Pipeline

The recommended middleware order:

```
1. ResolveAppContext    -> Detect channel from host/path
2. RateLimitByContext   -> Apply rate limits
3. AuthenticateChannel  -> JWT/API Key authentication
4. EnforceContextBinding-> Validate audience/tenant
5. RequireAbility       -> Check permissions (per-route)
6. InjectAuditContext   -> Inject context into logs
```

---

## Security Features

### Algorithm Confusion Prevention

The JWT verifier explicitly rejects the `none` algorithm (CVE-2015-9235):

```php
'jwt' => [
    'allowed_algorithms' => ['HS256', 'RS256', 'RS384', 'RS512'],
    // NEVER include 'none' here
],
```

### Audience Binding

Tokens are bound to their intended channel:

- Token with `aud=mobile` cannot access `/api/*` (admin channel)
- Token with `aud=admin` cannot access `/mobile/*`

### Tenant Binding

Multi-tenant isolation prevents cross-tenant access:

- Token with `tid=tenant_1` cannot access resources of `tenant_2`

### API Key Security

- **Argon2id hashing** (recommended) or Bcrypt
- **IP allowlist** with CIDR support (IPv4 and IPv6)
- **Optional global enforcement** of IP allowlists (`APP_CONTEXT_IP_ALLOWLIST=true`)
- **Automatic expiration** tracking
- **Async usage tracking** for performance

---

## Configuration Reference

### Environment Variables

```env
# Core
APP_CONTEXT_DOMAIN=myapp.com
APP_CONTEXT_DETECTION=auto
APP_CONTEXT_DENY_BY_DEFAULT=true

# Client Repository
APP_CONTEXT_CLIENT_DRIVER=config  # or 'eloquent'
APP_CONTEXT_CLIENTS_TABLE=api_clients
APP_CONTEXT_APPS_TABLE=api_apps
APP_CONTEXT_APP_KEYS_TABLE=api_app_keys
APP_CONTEXT_APP_MODEL=App\\Models\\ApiApp
APP_CONTEXT_APP_KEY_MODEL=App\\Models\\ApiAppKey
APP_CONTEXT_CLIENTS_CONNECTION=

# JWT
JWT_ALGO=RS256
JWT_ISSUER=https://myapp.com
JWT_TTL=3600
JWT_BLACKLIST_ENABLED=true
JWT_DEV_FALLBACK=true
JWT_DEV_ALGO=HS256

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

In local/staging environments, if RSA key files are missing and `JWT_DEV_FALLBACK=true`, the package falls back to symmetric signing using `JWT_DEV_SECRET`, `APP_KEY`, or a `dev-secret` fallback.

> **Recommendation:** Use RSA keys in production and disable the fallback there.

---

## Artisan Commands

### Generate API Key

```bash
php artisan app-context:generate-key "Client Name" [options]

Options:
  --channel=partner        Channel for the client
  --tenant=TENANT_ID       Tenant ID restriction
  --capabilities=*         Capabilities to grant (repeatable)
  --ip-allowlist=*         IP allowlist entries (repeatable)
  --expires=DATE           Expiration date (Y-m-d)
```

### List Clients

```bash
php artisan app-context:list-clients [options]

Options:
  --channel=CHANNEL        Filter by channel
  --tenant=TENANT_ID       Filter by tenant
  --include-revoked        Include revoked clients
```

### Revoke Key

```bash
php artisan app-context:revoke-key CLIENT_ID [options]

Options:
  --force                  Skip confirmation
```

---

## Testing

```bash
composer test

# Run specific test suite
./vendor/bin/phpunit tests/Unit/ClientRepositoryTest.php
```

---

## Upgrade Guide

### From v1.x to v2.x (Repository Pattern)

If you were using the library before the repository pattern was introduced:

1. Your existing `api_clients` table remains compatible
2. Set `APP_CONTEXT_CLIENT_DRIVER=eloquent` to maintain current behavior
3. (Recommended) Move to `api_apps` + `api_app_keys` and set the model/table config

---

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
