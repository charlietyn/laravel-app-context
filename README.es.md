# Laravel App Context (ES)

[![Latest Version on Packagist](https://img.shields.io/packagist/v/charlietyn/laravel-app-context.svg?style=flat-square)](https://packagist.org/packages/charlietyn/laravel-app-context)
[![Total Downloads](https://img.shields.io/packagist/dt/charlietyn/laravel-app-context.svg?style=flat-square)](https://packagist.org/packages/charlietyn/laravel-app-context)
[![License](https://img.shields.io/packagist/l/charlietyn/laravel-app-context.svg?style=flat-square)](https://packagist.org/packages/charlietyn/laravel-app-context)

Gestión multi‑canal de **app_context** para Laravel con autenticación JWT y API Key.

## Características

- 🔐 **Multi‑Auth**: JWT, API Key y anónimo
- 🎯 **Enrutamiento por canal**: detección por subdominio o path
- 🛡️ **Seguridad primero**: prevención de confusión de algoritmo, blacklist, binding por tenant
- 📊 **Rate limiting**: límites por canal/identidad
- 📝 **Audit logging**: contexto inyectado en logs
- 🔑 **Scopes/Capabilities**: soporte de comodines

## Requisitos

- PHP 8.2+
- Laravel 11.0+ o 12.0+
- php-open-source-saver/jwt-auth 2.0+

## Instalación

```bash
composer require charlietyn/laravel-app-context
```

Publica la configuración:

```bash
php artisan vendor:publish --tag=app-context-config
```

Publica y ejecuta migraciones:

```bash
php artisan vendor:publish --tag=app-context-migrations
php artisan migrate
```

## Inicio rápido

### 1. Configurar canales

Edita `config/app-context.php`:

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

### 2. Middleware

```php
// routes/api.php
Route::middleware(['app-context'])->group(function () {
    Route::get('/users', [UserController::class, 'index']);
});

// O middleware individuales
Route::middleware([
    'app.context',      // Resuelve el contexto
    'app.auth',         // Autentica
    'app.binding',      // Enforce bindings
    'app.throttle',     // Rate limit
    'app.audit',        // Audit logging
])->group(function () {
    // ...
});
```

### 3. Scopes requeridos

```php
Route::middleware(['app.scope:admin:users:read'])
    ->get('/api/users', [UserController::class, 'index']);

Route::middleware(['app.scope:admin:users:write,admin:users:delete'])
    ->delete('/api/users/{id}', [UserController::class, 'destroy']);
```

## Uso

### Acceso a AppContext

```php
use Ronu\AppContext\Facades\AppContext;

$context = AppContext::current();

if ($context->isAuthenticated()) {
    $userId = $context->getUserId();
}

if ($context->hasScope('admin:users:read')) {
    // ...
}
```

### En controladores

```php
use Ronu\AppContext\Context\AppContext;

class UserController extends Controller
{
    public function index(AppContext $context)
    {
        $context->requires('admin:users:read');
        
        return User::query()
            ->when($context->getTenantId(), fn($q, $tid) => $q->where('tenant_id', $tid))
            ->get();
    }
}
```

## Seguridad

### Prevención de confusión de algoritmo

El verificador JWT rechaza explícitamente `none`:

```php
'jwt' => [
    'allowed_algorithms' => ['HS256', 'RS256', 'RS384', 'RS512'],
],
```

### Requerimiento de `aud`

Con `JWT_VERIFY_AUD=true`, los tokens deben incluir el claim `aud`.

### Binding por audiencia y tenant

- `aud=mobile` no puede acceder a `/api/*` (admin).
- `tid=tenant_1` no puede acceder a recursos de `tenant_2`.

### Seguridad de API Keys

- Hash Argon2id o Bcrypt
- Allowlist de IP con CIDR
- Opción de enforcement global (`APP_CONTEXT_IP_ALLOWLIST=true`)
- Expiración automática y tracking de uso

## Revisión avanzada (mejoras y defectos)

### Mejoras recomendadas (seguridad/operación)

- **Bloqueo por defecto y detección estricta en entornos sensibles**: habilita `APP_CONTEXT_DENY_BY_DEFAULT=true` y considera `APP_CONTEXT_DETECTION=strict` para forzar que subdominio y path coincidan en el mismo canal, reduciendo riesgos de bypass por enrutamiento ambiguo.【F:config/app-context.php†L16-L63】
- **Endurecer JWT en producción**: usa RS256 con llaves dedicadas, `verify_iss`/`verify_aud` activos y desactiva el fallback de desarrollo (`JWT_DEV_FALLBACK=false`).【F:config/app-context.php†L284-L330】
- **Auditoría sin filtrar datos sensibles**: deja `include_request_body=false` y usa la lista de `sensitive_headers` para evitar leaks en logs; habilita la auditoría sólo cuando haya un pipeline seguro de logging.【F:config/app-context.php†L390-L429】
- **IP allowlist con proxies confiables**: si aplicas allowlists en API Keys, asegúrate de configurar `TrustProxies` en Laravel para que `Request::ip()` sea fiable; el paquete toma la IP directamente del request.【F:src/Auth/Verifiers/ApiKeyVerifier.php†L101-L108】

### Defectos y limitaciones actuales

- **Allowlist de IP limitada a IPv4**: la validación CIDR usa `ip2long`, por lo que las direcciones IPv6 no se evalúan correctamente.【F:src/Auth/Verifiers/ApiKeyVerifier.php†L214-L228】
- **`rate_limit_profile` no se usa**: aunque el canal define `rate_limit_profile`, el middleware toma el perfil por el ID del canal (`app-context.rate_limits.{canal}`), por lo que el parámetro no tiene efecto hoy.【F:config/app-context.php†L80-L161】【F:src/Middleware/RateLimitByContext.php†L73-L92】
- **`usage_count` no es atómico**: el conteo se incrementa con `usage_count + 1` en un `dispatch()->afterResponse()`, lo que puede perder incrementos bajo alta concurrencia.【F:src/Auth/Verifiers/ApiKeyVerifier.php†L233-L246】

### Plan de remediación (priorizado)

1. **Correctitud de rate limiting**
   - Conectar `rate_limit_profile` y el posible `rate_limit_tier` a la selección real del limiter (evitar hardcode por canal).【F:config/app-context.php†L80-L205】【F:src/Middleware/RateLimitByContext.php†L73-L122】
   - Implementar o eliminar `burst` para evitar una superficie de configuración engañosa.【F:config/app-context.php†L167-L245】【F:src/Middleware/RateLimitByContext.php†L73-L122】
2. **Seguridad y telemetría de API Keys**
   - Reemplazar `usage_count + 1` por un incremento atómico en DB (y considerar queue).【F:src/Auth/Verifiers/ApiKeyVerifier.php†L233-L246】
   - Añadir soporte IPv6 a los CIDR (p. ej. `inet_pton`) o documentar claramente la limitación a IPv4.【F:src/Auth/Verifiers/ApiKeyVerifier.php†L214-L228】
3. **Endurecimiento operativo de JWT**
   - Considerar desactivar lectura de tokens por query/cookie en producción para reducir exposición (preferir Authorization header).【F:src/Auth/Verifiers/JwtVerifier.php†L150-L175】
4. **Claridad del contexto anónimo/default**
   - Definir un canal `default` explícito o forzar `deny_by_default` en producción para evitar comportamiento implícito en rutas no mapeadas.【F:src/Middleware/ResolveAppContext.php†L44-L66】

## Configuración

### Variables de entorno

```env
# Core
APP_CONTEXT_DOMAIN=myapp.com
APP_CONTEXT_DETECTION=auto
APP_CONTEXT_DENY_BY_DEFAULT=true

# JWT
JWT_ALGO=RS256
JWT_ISSUER=https://myapp.com
JWT_TTL=3600
JWT_BLACKLIST_ENABLED=true
JWT_DEV_FALLBACK=true
JWT_DEV_ALGO=HS256
JWT_DEV_SECRET=base64:your-app-key

# API Key
API_KEY_HASH_ALGO=argon2id
API_KEY_ROTATION_DAYS=90
APP_CONTEXT_IP_ALLOWLIST=false

# Rate Limiting
RATE_LIMIT_MOBILE_GLOBAL=60/m
RATE_LIMIT_ADMIN_GLOBAL=120/m
RATE_LIMIT_PARTNER_GLOBAL=600/m
```

### Fallback de JWT en desarrollo

En entornos locales/staging, si faltan los archivos RSA y `JWT_DEV_FALLBACK=true`,
se usa un fallback simétrico (por defecto `HS256`) con `JWT_DEV_SECRET`, `APP_KEY`
o un fallback `dev-secret`.

> **Recomendación:** usa RSA en producción y deshabilita el fallback.

## Testing

```bash
composer test
```
