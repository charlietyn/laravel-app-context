# Module Route Loader (HelpersRouting)

## Overview
`HelpersRouting::loadModuleRoutes()` permite cargar archivos de rutas por patrón `glob` y aplicar namespace automáticamente para módulos.

## When to use / When NOT to use
**Úsalo cuando:**
- Tu app organiza rutas por módulos en carpetas (e.g. `modules/*/Routes/api.php`).

**Evítalo cuando:**
- No usas arquitectura modular basada en filesystem.

## How it works
- Busca archivos con `glob()`.
- Deriva el namespace `Modules\<Module>\Http\Controllers`.
- Agrupa rutas con `Route::group()`.

## Configuration
No requiere configuración. Se invoca desde tu propio `routes/*.php` o service provider.

## Usage examples
```php
use Ronu\AppContext\Helpers\HelpersRouting;

HelpersRouting::loadModuleRoutes('modules/*/Routes/api.php', 'admin');
```

## Edge cases / pitfalls
- Asume que el nombre del directorio del módulo coincide con el namespace.
- Solo funciona si la estructura de carpetas coincide con el patrón esperado.

## Evidence
- File: src/Helpers/HelpersRouting.php
  - Symbol: HelpersRouting::loadModuleRoutes()
  - Notes: carga de rutas por patrón y namespace.

## Related docs
- [Architecture](../03-architecture.md)
