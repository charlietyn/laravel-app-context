# Context Resolution (channel detection)

## Overview
Resuelve el **canal** (mobile/admin/site/partner) a partir de host y path para construir el `AppContext` base. Esto evita confiar en headers no firmados y define el `auth_mode` inicial del request.

## When to use / When NOT to use
**Úsalo cuando:**
- Necesitas separar flujos por canal (subdominio o prefijo de path).
- Quieres evitar spoofing de canal (headers no confiables).

**Evítalo cuando:**
- Tu app no tiene múltiples canales (una API simple puede usar auth estándar).

## How it works
- `ContextResolver` evalúa `detection_strategy` (`auto`, `path`, `subdomain`, `strict`).
- `ResolveAppContext` crea `AppContext` y lo inyecta en el request + container.
- Si `deny_by_default=true` y no hay canal, lanza excepción.

## Configuration
Keys relevantes:
- `detection_strategy`
- `auto_detection_rules`
- `domain`
- `channels.*.subdomains`
- `channels.*.path_prefixes`
- `deny_by_default`
- `default_channel`

## Usage examples
```php
// routes/api.php
Route::middleware(['app.context'])->group(function () {
    // Dentro ya existe AppContext
});
```

## Edge cases / pitfalls
- `domain` incorrecto rompe la extracción de subdominio en producción.
- En `strict`, subdominio y path deben coincidir con el mismo canal.
- Si `deny_by_default=true`, rutas sin canal configurado devolverán 403.

## Evidence
- File: src/Context/ContextResolver.php
  - Symbol: ContextResolver::resolve(), ContextResolver::resolveAuto(), ContextResolver::extractSubdomain()
  - Notes: estrategia de detección por host/path.
- File: src/Middleware/ResolveAppContext.php
  - Symbol: ResolveAppContext::handle()
  - Notes: creación e inyección del AppContext.
- File: config/app-context.php
  - Symbol: detection_strategy, auto_detection_rules, domain, channels, deny_by_default, default_channel
  - Notes: configuración de resolución por canal.

## Related docs
- [Configuration](../02-configuration.md)
- [Architecture](../03-architecture.md)
