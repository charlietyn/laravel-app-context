# Quickstart

This quickstart uses the built-in middleware group (`app-context`) and a minimal channel configuration.

## 1) Configure a channel

In `config/app-context.php`, ensure you have at least one channel configured. Example for a simple `site` channel:

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

## 2) Add the middleware group

Apply the `app-context` middleware group to routes you want to protect:

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

## 3) Verify the context

Send a request using `/site/profile` and observe:
- The channel should resolve to `site`
- `auth_mode` should be `jwt_or_anonymous`
- `scopes` should include `catalog:browse` when anonymous

[Back to index](../index.md)
