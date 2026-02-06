# Basic usage

This guide shows the minimal middleware pipeline and how to read the resolved context.

## 1) Apply the middleware group

The service provider registers an `app-context` middleware group that includes:
- `ResolveAppContext`
- `RateLimitByContext`
- `AuthenticateChannel`
- `EnforceContextBinding`
- `InjectAuditContext`

Apply it to the routes you want protected:

```php
use Illuminate\Support\Facades\Route;

Route::middleware(['app-context'])->group(function () {
    Route::get('/mobile/me', fn () => ['ok' => true]);
});
```

## 2) Read AppContext in controllers or routes

Use the facade or type-hint the context from the container:

```php
use Ronu\AppContext\Context\AppContext;
use Ronu\AppContext\Facades\AppContext as AppContextFacade;

Route::get('/admin/health', function (AppContext $context) {
    return response()->json([
        'app' => $context->getAppId(),
        'auth' => $context->getAuthMode(),
        'user_id' => $context->getUserId(),
    ]);
});

Route::get('/site/context', function () {
    return response()->json(AppContextFacade::toArray());
});
```

## 3) Enforce abilities on routes

Use middleware aliases to require scopes/capabilities:

```php
Route::middleware(['app-context', 'app.requires:admin:reports:read'])->group(function () {
    Route::get('/admin/reports', fn () => ['ok' => true]);
});
```

## 4) Use the custom auth guard (optional)

The package registers a guard named `app-context` that resolves users based on the context:

```php
// config/auth.php
'guards' => [
    'app-context' => [
        'driver' => 'app-context',
        'provider' => 'users',
    ],
],
```


## 5) Require JWT only on selected routes (optional-auth channels)

For channels using `jwt_or_anonymous`, you can keep most routes public and enforce authentication only on sensitive endpoints:

```php
Route::middleware(['app-context'])->group(function () {
    Route::get('/site/products', fn () => ['ok' => true]); // public

    Route::middleware(['app.auth.required:jwt', 'app.scope:users:write'])->group(function () {
        Route::post('/site/checkout', fn () => ['ok' => true]);
    });
});
```

## Evidence
- File: src/AppContextServiceProvider.php
  - Symbol: AppContextServiceProvider::registerMiddleware()
  - Notes: Registers the `app-context` middleware group and aliases.
- File: src/Middleware/ResolveAppContext.php
  - Symbol: ResolveAppContext::handle()
  - Notes: Resolves context, binds it to request attributes and the container.
- File: src/Context/AppContext.php
  - Symbol: AppContext::getAppId(), AppContext::getAuthMode(), AppContext::toArray()
  - Notes: Provides the getters and array export used in examples.
- File: src/Facades/AppContext.php
  - Symbol: AppContext::getFacadeAccessor()
  - Notes: Facade accessor for retrieving the current context.
