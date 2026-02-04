# Authorization (abilities, scopes, capabilities)

## Overview
Permite exigir permisos por ruta usando scopes (JWT) o capabilities (API Key). Incluye middlewares para **OR** y **AND**.

## When to use / When NOT to use
**Úsalo cuando:**
- Necesitas control granular por endpoint.
- Quieres la misma sintaxis para JWT y API keys.

**Evítalo cuando:**
- Tu app no necesita autorización por permiso (solo auth básica).

## How it works
- `RequireAbility` valida **OR** (al menos uno).
- `RequireAllAbilities` valida **AND** (todos).
- `RequireScope` soporta scopes y capabilities como legado.

## Configuration
Keys relevantes:
- `channels.<channel>.allowed_scopes`
- `channels.<channel>.allowed_capabilities`

## Usage examples
```php
Route::get('/admin/users', [UsersController::class, 'index'])
    ->middleware('app.requires:admin:users:read');

Route::post('/partner/orders', [OrdersController::class, 'store'])
    ->middleware('app.requires.all:partner:orders:create,partner:orders:sign');
```

## Edge cases / pitfalls
- `RequireAllAbilities` espera parámetros separados por coma (AND lógico).
- `RequireScope` es útil para compatibilidad, pero `app.requires` es el recomendado.

## Evidence
- File: src/Middleware/RequireAbility.php
  - Symbol: RequireAbility::handle()
  - Notes: OR lógico.
- File: src/Middleware/RequireAllAbilities.php
  - Symbol: RequireAllAbilities::handle()
  - Notes: AND lógico.
- File: src/Middleware/RequireScope.php
  - Symbol: RequireScope::handle()
  - Notes: middleware legacy scopes/capabilities.

## Related docs
- [Reference: middleware](../09-reference/middleware.md)
- [Feature: JWT Authentication](jwt-authentication.md)
- [Feature: API Key Authentication](api-key-authentication.md)
