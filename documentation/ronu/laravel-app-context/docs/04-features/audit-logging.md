# Audit Logging

## Overview
Inyecta el `AppContext` en el logger y permite registrar requests/responses con redacción de headers sensibles.

## When to use / When NOT to use
**Úsalo cuando:**
- Necesitas trazabilidad de requests por canal/usuario/cliente.
- Cumples requisitos de auditoría o compliance.

**Evítalo cuando:**
- Quieres reducir logs por performance (deshabilita o ajusta configuración).

## How it works
- `InjectAuditContext` toma config base + overrides por canal.
- `Log::shareContext()` agrega metadatos globales.
- Opcionalmente loguea request/response y filtra headers sensibles.

## Configuration
Keys relevantes:
- `audit.enabled`
- `audit.log_all_requests`
- `audit.include_request_body`
- `audit.include_response_body`
- `audit.sensitive_headers`
- `channels.<channel>.audit.*`

## Usage examples
```php
Route::middleware(['app.context', 'app.auth', 'app.audit'])
    ->get('/admin/stats', [StatsController::class, 'index']);
```

## Edge cases / pitfalls
- Evita habilitar `include_request_body` en endpoints con datos sensibles.
- Asegura que `sensitive_headers` incluya `authorization` y `x-api-key`.

## Evidence
- File: src/Middleware/InjectAuditContext.php
  - Symbol: InjectAuditContext::handle(), InjectAuditContext::filterHeaders(), InjectAuditContext::resolveConfig()
  - Notes: inyección de contexto y redacción.
- File: config/app-context.php
  - Symbol: audit, channels.*.audit
  - Notes: configuración base y por canal.

## Related docs
- [Security](../05-security.md)
- [Reference: middleware](../09-reference/middleware.md)
