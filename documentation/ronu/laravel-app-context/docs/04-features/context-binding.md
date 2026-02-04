# Context Binding (audience + tenant)

## Overview
Valida que el token o API key coincidan con el canal esperado y con el tenant del request. Previene ataques de **token reuse** y **cross-tenant access**.

## When to use / When NOT to use
**Úsalo cuando:**
- Tienes multi-tenant y necesitas aislamiento estricto.
- Sirves múltiples canales con tokens específicos por canal.

**Evítalo cuando:**
- Estás en una fase inicial y necesitas tolerancia (aunque se recomienda mantenerlo).

## How it works
- `EnforceContextBinding` verifica:
  - JWT: `aud` vs `AppContext::appId`
  - Tenant: `tid` vs tenant extraído de ruta/header/query
- Para `api_key`, valida tenant del request contra `client.tenantId`.

## Configuration
Keys relevantes:
- `jwt.verify_aud`
- `security.enforce_tenant_binding`
- `channels.<channel>.tenant_mode`

## Usage examples
```php
Route::middleware(['app.context', 'app.auth', 'app.binding'])
    ->get('/tenant/{tenant_id}/orders', [OrdersController::class, 'index']);
```

## Edge cases / pitfalls
- En `tenant_mode=multi`, si el token no tiene `tid`, se lanza `missingTenant()`.
- Si el request no incluye tenant, no hay validación de binding.

## Evidence
- File: src/Middleware/EnforceContextBinding.php
  - Symbol: EnforceContextBinding::handle(), EnforceContextBinding::validateJwtBinding(), EnforceContextBinding::validateTenantBinding()
  - Notes: validación de audience y tenant.
- File: config/app-context.php
  - Symbol: jwt.verify_aud, security.enforce_tenant_binding, channels.*.tenant_mode
  - Notes: toggles de binding.

## Related docs
- [Security](../05-security.md)
- [Reference: exceptions](../09-reference/exceptions.md)
