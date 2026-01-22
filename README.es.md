# Laravel App Context

[![Latest Version on Packagist](https://img.shields.io/packagist/v/ronu/laravel-app-context.svg?style=flat-square)](https://packagist.org/packages/ronu/laravel-app-context)
[![Total Downloads](https://img.shields.io/packagist/dt/ronu/laravel-app-context.svg?style=flat-square)](https://packagist.org/packages/ronu/laravel-app-context)
[![License](https://img.shields.io/packagist/l/ronu/laravel-app-context.svg?style=flat-square)](https://packagist.org/packages/ronu/laravel-app-context)

Gestión multi-canal de contexto de aplicación para Laravel con autenticación JWT y API Key.

> Documentación en inglés: [README.md](README.md)

## Características

- **Soporte Multi-Auth**: JWT, API Key y autenticación anónima
- **Enrutamiento por Canal**: Detección automática de canales por subdominio o path
- **Seguridad Primero**: Prevención de confusión de algoritmo, blacklist, binding por tenant
- **Rate Limiting**: Límites de tasa por contexto y canal
- **Audit Logging**: Inyección automática de contexto en logs
- **Sistema de Scopes/Capabilities**: Soporte de comodines para permisos
- **Almacenamiento Flexible de Clientes**: Config (sin BD), Eloquent o repositorios personalizados

## Requisitos

- PHP 8.2+
- Laravel 11.0+ o 12.0+
- php-open-source-saver/jwt-auth 2.0+

## Instalación

```bash
composer require ronu/laravel-app-context
```

Publica la configuración:

```bash
php artisan vendor:publish --tag=app-context-config
```

**Opcional** - Si usas el driver `eloquent`, crea las tablas en tu aplicación
(ejemplo de migración más abajo).

## Inicio Rápido

### 1. Configurar Canales

Edita `config/app-context.php` para definir tus canales:

```php
'channels' => [
    'mobile' => [
        'subdomains' => ['mobile', 'm'],
        'path_prefixes' => ['/mobile'],
        'auth_mode' => 'jwt',
        'jwt_audience' => 'mobile',
        'allowed_scopes' => ['mobile:*', 'user:profile:*'],
    ],

    'admin' => [
        'subdomains' => ['admin'],
        'path_prefixes' => ['/api'],
        'auth_mode' => 'jwt',
        'jwt_audience' => 'admin',
        'allowed_scopes' => ['admin:*'],
    ],

    'partner' => [
        'subdomains' => ['api-partners'],
        'path_prefixes' => ['/partner'],
        'auth_mode' => 'api_key',
        'allowed_capabilities' => ['partner:*'],
    ],
],
```

### 2. Aplicar Middleware

Agrega el grupo de middleware a tus rutas:

```php
// routes/api.php
Route::middleware(['app-context'])->group(function () {
    Route::get('/users', [UserController::class, 'index']);
});

// O usa middleware individuales
Route::middleware([
    'app.context',      // Resolver contexto
    'app.auth',         // Autenticar
    'app.binding',      // Aplicar bindings
    'app.throttle',     // Rate limit
    'app.audit',        // Audit logging
])->group(function () {
    // ...
});
```

### 3. Requerir Scopes

```php
Route::middleware(['app.scope:admin:users:read'])
    ->get('/api/users', [UserController::class, 'index']);

Route::middleware(['app.scope:admin:users:write,admin:users:delete'])
    ->delete('/api/users/{id}', [UserController::class, 'destroy']);
```

---

## Guía de Integración de Middleware

El paquete incluye middlewares granulares para armar un pipeline seguro por grupo de rutas:

| Middleware | Responsabilidad |
|------------|-----------------|
| `app.context` | Resolver canal + contexto |
| `app.auth` | Autenticar (JWT, API Key, anónimo) |
| `app.binding` | Enforzar binding de canal/tenant |
| `app.scope` | Validar scopes/capabilities |
| `app.throttle` | Rate limit por contexto |
| `app.audit` | Inyectar contexto en logs |

**Orden recomendado (rutas protegidas):**

```php
Route::middleware([
    'app.context',
    'app.auth',
    'app.binding',
    'app.throttle',
    'app.audit',
])->group(function () {
    // Rutas protegidas
});
```

**Endpoints de login (JWT):** resuelven contexto y aplican rate limit **sin** `app.auth`, luego generan el token.

```php
Route::middleware([
    'app.context',
    'app.binding',
    'app.throttle',
    'app.audit',
])->post('/api/login', [AuthController::class, 'login']);
```

**Endpoints con API Key:** no hay login. Cada request envía la key y `app.auth` la valida.

---

## Flujo de Login con `api_apps` + `api_app_keys`

Con el esquema de dos tablas, **`api_apps` es el registro de clientes** y **`api_app_keys` almacena las keys por cliente**:

1. **Crear una app** en `api_apps` con `app_code`, `app_name`, `is_active = true`.
2. **Crear una o más keys** en `api_app_keys` para esa app.
3. Autenticación con headers:
   - `X-Client-Id: <app_code>`
   - `X-Api-Key: <prefix>.<secret>`

**Login JWT (usuarios):**
- El endpoint de login solo necesita contexto (`app.context`) y auth normal de Laravel.
- El JWT debe incluir `aud` que coincida con el canal configurado.

**Login por API Key (M2M):**
- No existe login; cada request usa la key. La librería valida:
  - `api_apps.is_active`
  - `api_app_keys.revoked_at` + `expires_at`
  - `api_app_keys.scopes` o `api_app_keys.config.capabilities`

---

## Configuración del Repositorio de Clientes

La biblioteca usa un **patrón repositorio** para el almacenamiento de clientes API, permitiéndote elegir entre diferentes backends de almacenamiento sin modificar el código principal.

### Drivers Disponibles

| Driver | Requiere BD | Caso de Uso |
|--------|-------------|-------------|
| `config` | No | Configuraciones simples, pocos partners, despliegues stateless |
| `eloquent` | Sí | Gestión dinámica de clientes, muchos partners |
| Clase personalizada | Depende | Redis, API externa, almacenamiento personalizado |

### Estructura de Configuración

```php
// config/app-context.php
'client_repository' => [
    // Selección de driver: 'config', 'eloquent', o nombre de clase completo
    'driver' => env('APP_CONTEXT_CLIENT_DRIVER', 'config'),

    // Configuración para driver 'config'
    'config' => [
        'hash_algorithm' => env('API_KEY_HASH_ALGO', 'bcrypt'),
        'prefix_length' => 10,
        'key_length' => 32,
        'clients' => [
            // Definiciones de clientes aquí
        ],
    ],

    // Configuración para driver 'eloquent'
    'eloquent' => [
        // Esquema legacy en una sola tabla
        'table' => env('APP_CONTEXT_CLIENTS_TABLE', 'api_clients'),
        // Esquema multi-tabla (recomendado)
        'apps_table' => env('APP_CONTEXT_APPS_TABLE', 'api_apps'),
        'app_keys_table' => env('APP_CONTEXT_APP_KEYS_TABLE', 'api_app_keys'),
        // Opcional: clases de modelos
        'app_model' => env('APP_CONTEXT_APP_MODEL'),
        'app_key_model' => env('APP_CONTEXT_APP_KEY_MODEL'),
        'connection' => env('APP_CONTEXT_CLIENTS_CONNECTION', null),
        'hash_algorithm' => env('API_KEY_HASH_ALGO', 'argon2id'),
        'async_tracking' => true,
    ],
],
```

---

### Opción A: Driver Config (Sin Base de Datos)

El driver `config` te permite definir clientes API directamente en archivos de configuración. Es ideal para:

- Configuraciones simples con pocos partners
- Entornos de desarrollo y testing
- Despliegues stateless/serverless
- Enfoques de Infrastructure-as-Code

#### Paso 1: Generar Hash de la API Key

```bash
# Usando Laravel Tinker
php artisan tinker --execute="echo Hash::make('tu-api-key-secreta');"

# Output: $2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi
```

#### Paso 2: Definir Clientes en la Configuración

```php
// config/app-context.php
'client_repository' => [
    'driver' => 'config',

    'config' => [
        'hash_algorithm' => 'bcrypt', // or 'argon2id'

        'clients' => [
            // Identificador del cliente (usado como valor del header X-Client-Id)
            'acme-corp' => [
                'name' => 'ACME Corporation',
                'key_hash' => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
                'channel' => 'partner',
                'tenant_id' => null, // null = acceso a todos los tenants
                'capabilities' => [
                    'partner:orders:*',
                    'partner:inventory:read',
                    'webhooks:receive',
                ],
                'ip_allowlist' => [
                    '203.0.113.0/24',    // Notación CIDR soportada
                    '198.51.100.42',     // IP individual
                ],
                'is_active' => true,
                'is_revoked' => false,
                'expires_at' => '2025-12-31 23:59:59', // null = nunca expira
                'metadata' => [
                    'rate_limit_tier' => 'premium',
                    'webhook_url' => 'https://acme.example.com/webhooks',
                ],
            ],

            'beta-partner' => [
                'name' => 'Beta Partner',
                'key_hash' => '$2y$10$...', // Otro hash bcrypt
                'channel' => 'partner',
                'capabilities' => ['partner:orders:read'],
                'ip_allowlist' => [],
                'is_active' => true,
            ],
        ],
    ],
],
```

#### Paso 3: Usar la API Key

```bash
curl -X GET "https://api.example.com/partner/orders" \
  -H "X-Client-Id: acme-corp" \
  -H "X-Api-Key: tu-api-key-secreta"
```

#### Limitaciones del Driver Config

- No puede crear/revocar clientes en runtime (usa el helper `php artisan`)
- No hay tracking de uso (last_used_at, usage_count)
- Los cambios requieren actualizar el archivo de configuración

---

### Opción B: Driver Eloquent (Base de Datos)

El driver `eloquent` almacena clientes en una tabla de base de datos. Es ideal para:

- Gestión dinámica de clientes
- Gran número de partners
- Tracking de uso y analíticas
- Generación y revocación de keys en runtime

#### Paso 1: Configurar Variable de Entorno

```env
APP_CONTEXT_CLIENT_DRIVER=eloquent
```

#### Paso 2: Crear Tablas de Apps + Keys (Recomendado)

Crea migraciones para **`api_apps`** (clientes) y **`api_app_keys`** (keys por app).
Esto permite múltiples keys por cliente:

| Tabla | Columna | Descripción |
|-------|---------|-------------|
| `api_apps` | `app_code` | Identificador único del cliente (X-Client-Id) |
| `api_apps` | `app_name` | Nombre legible del cliente |
| `api_apps` | `is_active` | Estado activo |
| `api_apps` | `config` | JSON con channel, tenant_id, rate limits, etc. |
| `api_app_keys` | `app_id` | FK a `api_apps.id` |
| `api_app_keys` | `key_prefix` | Prefijo de la key |
| `api_app_keys` | `key_hash` | Hash Argon2id/Bcrypt |
| `api_app_keys` | `scopes` | Lista de scopes (texto/json) |
| `api_app_keys` | `config` | JSON con capabilities, ip_allowlist, etc. |
| `api_app_keys` | `expires_at` | Fecha de expiración |
| `api_app_keys` | `revoked_at` | Fecha de revocación |
| `api_app_keys` | `last_used_at` | Timestamp del último uso |
| `api_app_keys` | `last_used_ip` | IP del último request |
| `api_app_keys` | `last_user_agent` | User Agent del último request |

**Importante:** el driver `eloquent` también soporta el esquema legacy en una sola tabla (`api_clients`).

#### Paso 3: Indicar Modelos en la Configuración

```php
'client_repository' => [
    'driver' => 'eloquent',
    'eloquent' => [
        'app_model' => \App\Models\ApiApp::class,
        'app_key_model' => \App\Models\ApiAppKey::class,
    ],
],
```

#### Paso 3: Generar API Keys vía Artisan

```bash
# Generar una nueva API key
php artisan app-context:generate-key "Partner Company" \
    --channel=partner \
    --tenant=tenant_123 \
    --capabilities=partner:orders:create \
    --capabilities=partner:inventory:read \
    --ip-allowlist=203.0.113.0/24 \
    --expires=2025-12-31

# Listar todos los clientes
php artisan app-context:list-clients
php artisan app-context:list-clients --channel=partner
php artisan app-context:list-clients --include-revoked

# Revocar una key
php artisan app-context:revoke-key partner-company_abc123
php artisan app-context:revoke-key partner-company_abc123 --force
```

#### Opciones de Configuración Eloquent

```php
'eloquent' => [
    // Nombre legacy de una sola tabla
    'table' => 'my_api_clients',

    // Tablas multi-tabla
    'apps_table' => 'security.api_apps',
    'app_keys_table' => 'security.api_app_keys',

    // Clases de modelos opcionales
    'app_model' => \App\Models\ApiApp::class,
    'app_key_model' => \App\Models\ApiAppKey::class,

    // Usar una conexión de base de datos diferente
    'connection' => 'mysql_readonly',

    // Algoritmo de hash (argon2id recomendado para producción)
    'hash_algorithm' => 'argon2id',

    // Configuración de generación de keys
    'prefix_length' => 10,
    'key_length' => 32,

    // Tracking de uso asíncrono (recomendado para rendimiento)
    'async_tracking' => true,
],
```

---

### Opción C: Repositorio Personalizado

Puedes implementar tu propio backend de almacenamiento creando una clase que implemente `ClientRepositoryInterface`.

#### Paso 1: Crear Repositorio Personalizado

```php
<?php

namespace App\Repositories;

use Ronu\AppContext\Contracts\ClientRepositoryInterface;
use Ronu\AppContext\Support\ClientInfo;
use Illuminate\Support\Facades\Redis;

class RedisClientRepository implements ClientRepositoryInterface
{
    public function __construct(private array $config)
    {
        // Initialize with config from app-context.php
    }

    public function findByAppCode(string $appCode, ?string $keyPrefix = null): ?ClientInfo
    {
        $data = Redis::hgetall("api_apps:{$appCode}");

        if (empty($data)) {
            return null;
        }

        return ClientInfo::fromArray([
            'app_code' => $appCode,
            'name' => $data['name'],
            'key_hash' => $data['key_hash'],
            'channel' => $data['channel'],
            'tenant_id' => $data['tenant_id'] ?? null,
            'capabilities' => json_decode($data['capabilities'] ?? '[]', true),
            'ip_allowlist' => json_decode($data['ip_allowlist'] ?? '[]', true),
            'is_active' => (bool) ($data['is_active'] ?? true),
            'is_revoked' => (bool) ($data['is_revoked'] ?? false),
            'expires_at' => $data['expires_at'] ?? null,
        ]);
    }

    public function verifyKeyHash(string $key, string $storedHash): bool
    {
        return password_verify($key, $storedHash);
    }

    public function trackUsage(
        string $appCode,
        string $ip,
        ?string $keyPrefix = null,
        ?string $userAgent = null
    ): void
    {
        Redis::hincrby("api_apps:{$appCode}", 'usage_count', 1);
        Redis::hset("api_apps:{$appCode}", 'last_used_ip', $ip);
        Redis::hset("api_apps:{$appCode}", 'last_used_at', now()->toIso8601String());
    }

    public function generateKey(): array
    {
        $prefix = \Illuminate\Support\Str::random(10);
        $secret = \Illuminate\Support\Str::random(32);
        $key = "{$prefix}.{$secret}";

        return [
            'key' => $key,
            'hash' => password_hash($key, PASSWORD_ARGON2ID),
            'prefix' => $prefix,
        ];
    }

    public function create(array $data): ClientInfo
    {
        // Implement Redis storage logic
    }

    public function revoke(string $appCode): bool
    {
        return Redis::hset("api_apps:{$appCode}", 'is_revoked', '1') > 0;
    }

    public function all(array $filters = []): iterable
    {
        // Implement listing logic
    }
}
```

#### Paso 2: Configurar Driver Personalizado

```php
// config/app-context.php
'client_repository' => [
    'driver' => \App\Repositories\RedisClientRepository::class,

    // Configuración personalizada pasada al constructor del repositorio
    \App\Repositories\RedisClientRepository::class => [
        'prefix' => 'api_apps',
        'connection' => 'default',
    ],
],
```

---

## Uso

### Acceso a AppContext

```php
use Ronu\AppContext\Facades\AppContext;

// Obtener contexto actual
$context = AppContext::current();

// Verificar autenticación
if ($context->isAuthenticated()) {
    $userId = $context->getUserId();
}

// Verificar permisos
if ($context->hasScope('admin:users:read')) {
    // ...
}

// Requerir permiso (lanza excepción si falta)
$context->requires('admin:export:run');
```

### En Controladores

```php
use Ronu\AppContext\Context\AppContext;

class UserController extends Controller
{
    public function index(AppContext $context)
    {
        // Context is injected via DI
        $context->requires('admin:users:read');

        return User::query()
            ->when($context->getTenantId(), fn($q, $tid) => $q->where('tenant_id', $tid))
            ->get();
    }
}
```

### Usando el Trait HasAppContext

```php
use Ronu\AppContext\Traits\HasAppContext;

class OrderController extends Controller
{
    use HasAppContext;

    public function index()
    {
        // Access context via trait
        if ($this->appContext()->hasCapability('partner:orders:read')) {
            return Order::forTenant($this->appContext()->getTenantId())->get();
        }
    }
}
```

---

## Pipeline de Middleware

El orden de middleware recomendado:

```
1. ResolveAppContext    -> Detectar canal desde host/path
2. AuthenticateChannel  -> Autenticación JWT/API Key
3. EnforceContextBinding-> Validar audience/tenant
4. RateLimitByContext   -> Aplicar rate limits
5. InjectAuditContext   -> Inyectar contexto en logs
6. RequireScope         -> Verificar permisos (por ruta)
```

---

## Características de Seguridad

### Prevención de Confusión de Algoritmo

El verificador JWT rechaza explícitamente el algoritmo `none` (CVE-2015-9235):

```php
'jwt' => [
    'allowed_algorithms' => ['HS256', 'RS256', 'RS384', 'RS512'],
    // NUNCA incluir 'none' aquí
],
```

### Binding por Audiencia

Los tokens están vinculados a su canal previsto:

- Token con `aud=mobile` no puede acceder a `/api/*` (canal admin)
- Token con `aud=admin` no puede acceder a `/mobile/*`

### Binding por Tenant

El aislamiento multi-tenant previene acceso entre tenants:

- Token con `tid=tenant_1` no puede acceder a recursos de `tenant_2`

### Seguridad de API Keys

- **Hash Argon2id** (recomendado) o Bcrypt
- **IP allowlist** con soporte CIDR (IPv4 e IPv6)
- **Enforcement global opcional** de IP allowlists (`APP_CONTEXT_IP_ALLOWLIST=true`)
- **Tracking automático de expiración**
- **Tracking de uso asíncrono** para rendimiento

---

## Referencia de Configuración

### Variables de Entorno

```env
# Core
APP_CONTEXT_DOMAIN=myapp.com
APP_CONTEXT_DETECTION=auto
APP_CONTEXT_DENY_BY_DEFAULT=true

# Client Repository
APP_CONTEXT_CLIENT_DRIVER=config  # or 'eloquent'
APP_CONTEXT_CLIENTS_TABLE=api_clients
APP_CONTEXT_APPS_TABLE=api_apps
APP_CONTEXT_APP_KEYS_TABLE=api_app_keys
APP_CONTEXT_APP_MODEL=App\\Models\\ApiApp
APP_CONTEXT_APP_KEY_MODEL=App\\Models\\ApiAppKey
APP_CONTEXT_CLIENTS_CONNECTION=

# JWT
JWT_ALGO=RS256
JWT_ISSUER=https://myapp.com
JWT_TTL=3600
JWT_BLACKLIST_ENABLED=true
JWT_DEV_FALLBACK=true
JWT_DEV_ALGO=HS256

# API Key
API_KEY_HASH_ALGO=argon2id
API_KEY_ROTATION_DAYS=90
APP_CONTEXT_IP_ALLOWLIST=false

# Rate Limiting
RATE_LIMIT_MOBILE_GLOBAL=60/m
RATE_LIMIT_ADMIN_GLOBAL=120/m
RATE_LIMIT_PARTNER_GLOBAL=600/m
```

### Fallback de Desarrollo para JWT Keys

En entornos locales/staging, si faltan los archivos de claves RSA y `JWT_DEV_FALLBACK=true`, el paquete usa firma simétrica con `JWT_DEV_SECRET`, `APP_KEY`, o un fallback `dev-secret`.

> **Recomendación:** Usa claves RSA en producción y desactiva el fallback allí.

---

## Comandos Artisan

### Generar API Key

```bash
php artisan app-context:generate-key "Nombre del Cliente" [opciones]

Opciones:
  --channel=partner        Canal para el cliente
  --tenant=TENANT_ID       Restricción de tenant ID
  --capabilities=*         Capabilities a otorgar (repetible)
  --ip-allowlist=*         Entradas de IP allowlist (repetible)
  --expires=FECHA          Fecha de expiración (Y-m-d)
```

### Listar Clientes

```bash
php artisan app-context:list-clients [opciones]

Opciones:
  --channel=CHANNEL        Filtrar por canal
  --tenant=TENANT_ID       Filtrar por tenant
  --include-revoked        Incluir clientes revocados
```

### Revocar Key

```bash
php artisan app-context:revoke-key CLIENT_ID [opciones]

Opciones:
  --force                  Saltar confirmación
```

---

## Testing

```bash
composer test

# Ejecutar suite de tests específica
./vendor/bin/phpunit tests/Unit/ClientRepositoryTest.php
```

---

## Guía de Actualización

### De v1.x a v2.x (Patrón Repositorio)

Si estabas usando la biblioteca antes de la introducción del patrón repositorio:

1. Tu tabla `api_clients` existente sigue siendo compatible
2. Configura `APP_CONTEXT_CLIENT_DRIVER=eloquent` para mantener el comportamiento actual
3. (Recomendado) Migrar a `api_apps` + `api_app_keys` y setear la configuración de modelos/tablas

---

## Licencia

La Licencia MIT (MIT). Por favor consulta el [Archivo de Licencia](LICENSE) para más información.
