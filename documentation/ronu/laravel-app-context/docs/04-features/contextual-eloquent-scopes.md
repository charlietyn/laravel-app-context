# Contextual Eloquent Scopes

## Overview
El trait `ContextualScopes` aplica filtros automáticos por tenant y usuario en modelos Eloquent, y puede autocompletar `tenant_id` y `user_id` en `creating`.

## When to use / When NOT to use
**Úsalo cuando:**
- Necesitas aislamiento multi-tenant y/o multi-user a nivel de modelo.

**Evítalo cuando:**
- Tu app no tiene tenant/user en tablas o usas filtros manuales complejos.

## How it works
- `scopeForContext()` filtra por `tenant_id` y (si no es admin) `user_id`.
- `bootContextualScopes()` autopuebla columnas si están disponibles.

## Configuration
No requiere config. Puede personalizar columnas con `$tenantColumn` y `$userColumn` en el modelo.

## Usage examples
```php
use Ronu\AppContext\Traits\ContextualScopes;

class Order extends Model
{
    use ContextualScopes;
}

// En controlador
Order::forContext()->get();
Order::forTenant()->get();
```

## Edge cases / pitfalls
- El trait detecta columnas via `fillable` o `Schema`.
- En canal `admin`, `scopeForContext()` mantiene filtros de tenant/user solo si no es admin.

## Evidence
- File: src/Traits/ContextualScopes.php
  - Symbol: ContextualScopes::scopeForContext(), ContextualScopes::bootContextualScopes()
  - Notes: filtros y auto-fill.

## Related docs
- [Feature: Context Resolution](context-resolution.md)
