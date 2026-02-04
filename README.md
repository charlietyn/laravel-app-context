# Laravel App Context

[![Latest Version on Packagist](https://img.shields.io/packagist/v/ronu/laravel-app-context.svg?style=flat-square)](https://packagist.org/packages/ronu/laravel-app-context)
[![Total Downloads](https://img.shields.io/packagist/dt/ronu/laravel-app-context.svg?style=flat-square)](https://packagist.org/packages/ronu/laravel-app-context)
[![License](https://img.shields.io/packagist/l/ronu/laravel-app-context.svg?style=flat-square)](https://packagist.org/packages/ronu/laravel-app-context)

**Multi-channel application context management for Laravel** (JWT + API key auth) with channel detection, context-aware rate limiting, and audit logging.

- **Documentation:** [documentation/index.md](documentation/index.md)

## Requirements

- PHP 8.2+
- Laravel 11.x or 12.x
- `php-open-source-saver/jwt-auth` 2.x

## Installation

```bash
composer require ronu/laravel-app-context
```

Publish config:

```bash
php artisan vendor:publish --tag=app-context-config
```

## Quickstart

1) Configure a channel in `config/app-context.php`:

```php
'channels' => [
    'site' => [
        'subdomains' => ['www', null],
        'path_prefixes' => ['/site'],
        'auth_mode' => 'jwt_or_anonymous',
        'jwt_audience' => 'site',
        'allowed_scopes' => ['site:*', 'catalog:browse'],
        'public_scopes' => ['catalog:browse'],
        'rate_limit_profile' => 'site',
        'tenant_mode' => 'single',
        'features' => [
            'allow_anonymous' => true,
        ],
    ],
],
```

2) Apply the middleware group:

```php
use Illuminate\Support\Facades\Route;
use Ronu\AppContext\Facades\AppContext;

Route::middleware(['app-context'])->group(function () {
    Route::get('/site/profile', function () {
        return response()->json([
            'channel' => AppContext::getAppId(),
            'auth_mode' => AppContext::getAuthMode(),
            'scopes' => AppContext::getScopes(),
        ]);
    });
});
```

## Configuration

- Config lives in `config/app-context.php` (publish tag: `app-context-config`).
- Environment variable reference: [documentation/02-configuration/01-env-vars.md](documentation/02-configuration/01-env-vars.md)
- Full config reference: [documentation/02-configuration/00-configuration-reference.md](documentation/02-configuration/00-configuration-reference.md)

## Common scenarios

### 1) Mobile app with JWT scopes
```php
Route::middleware(['app-context', 'app.requires:mobile:orders:read'])->group(function () {
    Route::get('/mobile/orders', fn () => ['ok' => true]);
});
```

### 2) Partner API with API keys
```php
Route::middleware(['app-context', 'app.requires:partner:orders:read'])->group(function () {
    Route::get('/partner/orders', fn () => ['ok' => true]);
});
```

### 3) Admin dashboard (subdomain detection)
```php
Route::middleware(['app-context', 'app.scope:admin:*'])->group(function () {
    Route::get('/api/admin/metrics', fn () => ['ok' => true]);
});
```

More scenarios: [documentation/03-usage/02-scenarios.md](documentation/03-usage/02-scenarios.md)

## Edge scenarios

Common edge cases include config caching, queue workers, burst traffic, tenant mismatches, and JWT blacklist races.

See: [documentation/03-usage/03-edge-and-extreme-scenarios.md](documentation/03-usage/03-edge-and-extreme-scenarios.md)

## API reference

- [Public API](documentation/04-reference/00-public-api.md)
- [Middleware](documentation/04-reference/02-middleware.md)
- [Artisan commands](documentation/04-reference/01-artisan-commands.md)

## Troubleshooting

Start here: [documentation/05-quality/02-troubleshooting.md](documentation/05-quality/02-troubleshooting.md)

## Contributing / Security

- [Security](documentation/05-quality/00-security.md)
- [Testing](documentation/05-quality/01-testing.md)

---

**Start here:** [documentation/index.md](documentation/index.md)
