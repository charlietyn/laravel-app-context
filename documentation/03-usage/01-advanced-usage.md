# Advanced usage

## Custom client repository

You can provide a custom repository class by setting `client_repository.driver` to a fully qualified class name that implements `ClientRepositoryInterface`:

```php
// config/app-context.php
'client_repository' => [
    'driver' => App\Repositories\PartnerClientRepository::class,
    App\Repositories\PartnerClientRepository::class => [
        'endpoint' => 'https://clients.internal/api',
    ],
],
```

Your repository must implement:
- `findByAppCode()`
- `verifyKeyHash()`
- `trackUsage()`
- `generateKey()`
- `create()`
- `revoke()`
- `all()`

## Context-aware API resources

Extend `ContextAwareResource` to return fields based on the channel:

```php
use Illuminate\Http\Request;
use Ronu\AppContext\Resources\ContextAwareResource;

class UserResource extends ContextAwareResource
{
    protected function toPublicArray(Request $request): array
    {
        return ['id' => $this->id, 'name' => $this->name];
    }

    protected function toFullArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'email' => $this->email,
        ];
    }
}
```

## Contextual Eloquent scopes

Use `ContextualScopes` in models to filter by tenant/user automatically:

```php
use Illuminate\Database\Eloquent\Model;
use Ronu\AppContext\Traits\ContextualScopes;

class Order extends Model
{
    use ContextualScopes;
}

$orders = Order::forContext()->get();
```

## Module route loading helper

If you organize routes by module, you can load them with a helper that applies a namespace:

```php
use Ronu\AppContext\Helpers\HelpersRouting;

HelpersRouting::loadModuleRoutes('modules/*/Routes/api.php', 'admin');
```

## Optional JWT authentication

For `jwt_or_anonymous` channels, the JWT authenticator will attempt to authenticate, but can fall back to anonymous access when configured.

## Evidence
- File: src/AppContextServiceProvider.php
  - Symbol: AppContextServiceProvider::registerClientRepository()
  - Notes: Supports `config`, `eloquent`, or custom repository classes.
- File: src/Contracts/ClientRepositoryInterface.php
  - Symbol: ClientRepositoryInterface
  - Notes: Interface your custom repository must implement.
- File: src/Resources/ContextAwareResource.php
  - Symbol: ContextAwareResource::toArray()
  - Notes: Resolves output based on channel.
- File: src/Traits/ContextualScopes.php
  - Symbol: ContextualScopes::scopeForContext()
  - Notes: Filters models by tenant/user context.
- File: src/Helpers/HelpersRouting.php
  - Symbol: HelpersRouting::loadModuleRoutes()
  - Notes: Loads module routes with a namespace and route group.
- File: src/Auth/Authenticators/JwtAuthenticator.php
  - Symbol: JwtAuthenticator::authenticate(), JwtAuthenticator::tryAuthenticate()
  - Notes: Implements optional JWT authentication for `jwt_or_anonymous` channels.
