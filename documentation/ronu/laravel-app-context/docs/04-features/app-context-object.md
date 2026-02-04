# AppContext Object (Facade + Trait)

## Overview
`AppContext` es un value object inmutable que representa identidad, permisos, tenant y metadata por request. Se expone vía Facade y el trait `HasAppContext` para controllers.

## When to use / When NOT to use
**Úsalo cuando:**
- Necesitas leer `appId`, `userId`, `clientId`, `scopes` o `tenantId` en controllers/services.

**Evítalo cuando:**
- Tu lógica ya está completamente en middleware y no necesitas acceso en runtime.

## How it works
- `ResolveAppContext` crea y registra el `AppContext` en el request/IoC.
- La Facade `AppContext` lee del contenedor `app-context`.
- `HasAppContext` facilita helpers en controllers.

## Configuration
No requiere configuración específica.

## Usage examples
```php
use Ronu\AppContext\Facades\AppContext;

if (AppContext::isResolved()) {
    $channel = AppContext::getAppId();
}
```

```php
use Ronu\AppContext\Traits\HasAppContext;

class MyController extends Controller
{
    use HasAppContext;

    public function index()
    {
        if ($this->isAuthenticated()) {
            return $this->userId();
        }
    }
}
```

## Edge cases / pitfalls
- Si el middleware `app.context` no corre, el contexto no existe y la Facade puede devolver null.

## Evidence
- File: src/Context/AppContext.php
  - Symbol: AppContext::fromChannel(), AppContext::fromJwt(), AppContext::fromApiKey()
  - Notes: value object principal.
- File: src/Facades/AppContext.php
  - Symbol: AppContext::current(), AppContext::isResolved()
  - Notes: acceso vía Facade.
- File: src/Traits/HasAppContext.php
  - Symbol: HasAppContext::context(), HasAppContext::isAuthenticated()
  - Notes: helpers para controllers.
- File: src/Middleware/ResolveAppContext.php
  - Symbol: ResolveAppContext::handle()
  - Notes: inyección en request/IoC.

## Related docs
- [Architecture](../03-architecture.md)
- [Reference: middleware](../09-reference/middleware.md)
