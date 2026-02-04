# Rate Limiting por contexto

## Overview
Aplica límites por canal, endpoint y contexto (user, client, IP). Soporta burst limits y headers estándar.

## When to use / When NOT to use
**Úsalo cuando:**
- Necesitas proteger endpoints críticos por canal.
- Debes diferenciar límites entre autenticados y anónimos.

**Evítalo cuando:**
- No tienes tráfico significativo o usas otro sistema de rate limiting centralizado.

## How it works
- `RateLimitByContext` lee perfil por canal (`rate_limits`).
- Determina la clave según `by` (user, client_id, ip, user_device).
- Aplica límites globales o específicos por endpoint.

## Configuration
Keys relevantes:
- `rate_limits.<profile>.global`
- `rate_limits.<profile>.authenticated_global`
- `rate_limits.<profile>.by`
- `rate_limits.<profile>.burst`
- `rate_limits.<profile>.endpoints`
- `channels.<channel>.rate_limit_profile`

## Usage examples
```php
// config/app-context.php
'rate_limits' => [
    'admin' => [
        'global' => '120/m',
        'by' => 'user',
        'burst' => '20/s',
        'endpoints' => [
            'GET:/api/reports/export' => '5/m',
        ],
    ],
],
```

```php
Route::middleware(['app.context', 'app.throttle'])->group(function () {
    // rutas con rate limiting por contexto
});
```

## Edge cases / pitfalls
- Si usas `app.throttle`, evita doble rate limiting con `throttle:api`.
- `endpoint` soporta `*` por segmento, no regex completo.

## Evidence
- File: src/Middleware/RateLimitByContext.php
  - Symbol: RateLimitByContext::handle(), RateLimitByContext::getRateLimitConfig(), RateLimitByContext::matchEndpoint()
  - Notes: implementación de rate limiting y patrones.
- File: config/app-context.php
  - Symbol: rate_limits, channels.*.rate_limit_profile
  - Notes: perfiles y binding a canales.

## Related docs
- [Configuration](../02-configuration.md)
- [Security](../05-security.md)
