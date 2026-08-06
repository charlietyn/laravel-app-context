# Configuracion de Multi-Tenancy

## Vision General

El sistema de multi-tenancy es **completamente opcional y configurable**. Puede ser:
- **Habilitado globalmente** para toda la aplicacion
- **Habilitado por canal** (admin multi-tenant, site single-tenant)
- **Habilitado por modelo** (algunos modelos globales, otros tenant-aware)
- **Auto-detectado** basado en la configuracion de canales en `app-context.php`

## Configuracion

### Variables de Entorno

```ini
# Habilitar/deshabilitar tenancy globalmente
TENANCY_ENABLED=true          # true | false | (vacio = auto-detect)

# Modo de enforcement
TENANCY_ENFORCEMENT_MODE=strict  # strict | soft | disabled

# Overrides por canal (dejar vacio para heredar de app-context.channels.*.tenant_mode)
TENANCY_ADMIN_ENABLED=
TENANCY_MOBILE_ENABLED=
TENANCY_SITE_ENABLED=
TENANCY_PARTNER_ENABLED=

# Auditoria
TENANCY_LOG_BYPASSES=true
TENANCY_ALERT_VIOLATIONS=true
```

### Archivo de Configuracion (`config/tenancy.php`)

| Opcion | Valores | Default | Descripcion |
|--------|---------|---------|-------------|
| `enabled` | `true`, `false`, `null` | `null` | Master switch (`null` = auto-detect) |
| `enforcement_mode` | `strict`, `soft`, `disabled` | `strict` | Comportamiento sin contexto |
| `tenant_column` | string | `tenant_id` | Nombre de columna por defecto |
| `channels.*` | `true`, `false`, `null` | `null` | Override por canal (`null` = hereda de app-context) |
| `exempt_models` | array | `[...]` | Modelos excluidos de tenancy |
| `performance.cache_context` | boolean | `true` | Cachear contexto |
| `audit.log_bypasses` | boolean | `true` | Loguear bypasses |

## Integracion con AppContext

El `TenantContextManager` se integra con el sistema `AppContext` existente:

1. El middleware `ctx.auth` resuelve el JWT y extrae `tid` (tenant ID) en `AppContext`
2. El middleware `TenantOwnershipValidator` lee el `tenantId` de `AppContext` y lo inyecta en `TenantContextManager`
3. `TenantScope` consulta `TenantContextManager` antes de aplicar el filtro WHERE
4. `TenantAware` trait consulta `TenantContextManager` para auto-set en creating y validar en updating

La resolucion de canal-tenancy sigue este orden:
1. Override explicito en `config('tenancy.channels.{canal}')` (si no es null)
2. Valor de `tenant_mode` en `config('app-context.channels.{canal}.tenant_mode')`
3. Default: habilitado

## Casos de Uso

### Caso 1: Aplicacion Completamente Multi-Tenant

```ini
TENANCY_ENABLED=true
TENANCY_ENFORCEMENT_MODE=strict
```

Todos los canales con `tenant_mode=multi` tendran aislamiento.
Queries sin contexto fallan con excepcion.

### Caso 2: Aplicacion Single-Tenant

```ini
TENANCY_ENABLED=false
```

Zero overhead. Todo el codigo de tenancy se bypassa.

### Caso 3: Hibrido (Admin multi-tenant, Site publico)

```ini
TENANCY_ENABLED=true
TENANCY_ENFORCEMENT_MODE=soft
```

El canal `admin` tiene `tenant_mode=multi` en app-context -> aislamiento.
El canal `site` tiene `tenant_mode=single` en app-context -> sin filtro.
Soft mode permite queries sin contexto en CLI/jobs.

### Caso 4: Auto-Deteccion

```ini
# Dejar TENANCY_ENABLED vacio o no definirlo
```

El sistema escanea `config/app-context.php` y si encuentra al menos un canal
con `tenant_mode=multi`, habilita tenancy automaticamente.

## Arquitectura

### Componentes

| Componente | Archivo | Responsabilidad |
|---|---|---|
| `TenantContextManager` | `app/Services/Tenancy/TenantContextManager.php` | Almacena/resuelve tenant_id, bypass, enforcement |
| `TenantScope` | `app/Scopes/TenantScope.php` | Global scope que aplica WHERE tenant_id = ? |
| `TenantAware` | `app/Traits/TenantAware.php` | Trait para modelos: auto-set, validacion, scope |
| `TenantOwnershipValidator` | `app/Http/Middleware/TenantOwnershipValidator.php` | Middleware que hidrata contexto desde AppContext |
| `tenancy.php` | `config/tenancy.php` | Configuracion centralizada |

### Flujo de Request

```
Request HTTP
  -> ResolveAppContext (detecta canal)
  -> AuthenticateChannel (JWT/API key -> AppContext con tenantId)
  -> EnforceContextBinding (valida JWT.aud == canal)
  -> TenantOwnershipValidator (hidrata TenantContextManager)
  -> Controller
    -> Model::query() -> TenantScope::apply() -> WHERE tenant_id = ?
```

### Modelos Exentos

Los siguientes modelos NUNCA tienen tenancy aplicado:

- `Modules\location\Models\Countries` (tabla de lookup)
- `Modules\location\Models\States` (tabla de lookup)
- `Modules\core\Models\Tenants` (tabla de sistema)
- `App\Models\Error_logs` (logs globales)

Configurar en `config/tenancy.php` -> `exempt_models`.

## Optimizaciones de Performance

### Cuando Tenancy Esta Deshabilitado

- `TenantScope::apply()` retorna inmediatamente (0 overhead)
- `TenantAware::bootTenantAware()` no registra event listeners
- `TenantContextManager::setTenantId()` es no-op
- Middleware de validacion se salta completamente

### Cuando Tenancy Esta Habilitado

El overhead es minimo (~2-5%):
- Una llamada a `config()` cacheada por request
- Un WHERE adicional por query (usa indice en tenant_id)

## Seguridad

### Prevenir Bypasses Accidentales

```php
// Solo superadmin puede usar withoutTenant / forTenant
User::withoutTenant()->get();    // Requiere is_superuser
User::forTenant('other-id');     // Requiere is_superuser
```

### Prevenir Modificacion de tenant_id

El trait `TenantAware` bloquea cambios en `tenant_id` durante `updating`.
Cualquier intento logea un error y lanza excepcion.

## Diagnostico

```bash
# Ver estado actual de configuracion
php artisan tenancy:status

# Con analisis detallado de modelos
php artisan tenancy:status --detailed
```

## Testing

```php
// Deshabilitar tenancy en tests especificos
Config::set('tenancy.enabled', false);
$tenantManager->reset();

// Habilitar con modo soft para tests
Config::set('tenancy.enabled', true);
Config::set('tenancy.enforcement_mode', 'soft');
$tenantManager->reset();
```

## Evidence

- File: config/tenancy.php
  - Symbol/Area: Configuracion completa de tenancy
  - Notes: Todas las opciones documentadas con valores por defecto
- File: app/Services/Tenancy/TenantContextManager.php
  - Symbol/Area: Servicio principal
  - Notes: Integra con AppContext existente
- File: config/app-context.php
  - Symbol/Area: channels.*.tenant_mode
  - Notes: Fuente primaria para deteccion de canal multi/single
