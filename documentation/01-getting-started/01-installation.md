# Installation

## 1) Install the package

```bash
composer require ronu/laravel-app-context
```

## 2) Publish configuration

```bash
php artisan vendor:publish --tag=app-context-config
```

This publishes `config/app-context.php`.

## 3) (Optional) Configure JWT keys

If you are using JWT authentication, configure `jwt-auth` (the package is already required by Composer). You can use symmetric (HS256) or RSA (RS256) keys based on your configuration.

**Next:** [Quickstart](02-quickstart.md)

[Back to index](../index.md)
