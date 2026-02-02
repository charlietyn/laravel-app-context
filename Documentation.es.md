# Resumen de hallazgos del repositorio

- Nombre del paquete: `ronu/laravel-app-context` con soporte Laravel 11/12 y JWT vía `php-open-source-saver/jwt-auth`. El service provider es `Ronu\AppContext\AppContextServiceProvider`.
- Middleware incluidos: `app.context`, `app.auth`, `app.binding`, `app.scope`, `app.throttle`, `app.audit`, y el grupo `app-context`.
- La configuración está en `config/app-context.php` (canales, repositorio de clientes, JWT, API keys, rate limiting, seguridad, auditoría, rutas públicas).
- Almacenamiento: clientes en config o repositorios con base de datos (legacy `api_clients` o recomendado `api_apps` + `api_app_keys`).
- La verificación JWT incluye chequeo estricto de algoritmos y validación de audiencia/issuer; la verificación de API key usa headers `X-Client-Id` y `X-Api-Key` por defecto.

# Documentación

## 1) Título + Resumen de un párrafo

**Laravel App Context – Contexto multicanal + seguridad JWT/API Key**

Este paquete proporciona resolución determinista de contexto de aplicación (canal + tenant + modo de autenticación), orden de middleware estandarizado, integración JWT/API key y rate limiting/logging con contexto para Laravel 11/12. Resuelve el contexto solo desde host/path (nunca desde headers no firmados), vincula tokens a canal y tenant, y expone un objeto único `AppContext` para decisiones de autorización. Todo se registra vía `Ronu\AppContext\AppContextServiceProvider`, con configuración en `config/app-context.php`.

## 2) Inicio rápido (5–10 pasos)

1) Instala el paquete con Composer (ver Instalación).
2) Publica la configuración: `php artisan vendor:publish --tag=app-context-config`.
3) Configura `config/app-context.php` con canales (`mobile`, `admin`, `partner`) y su `auth_mode`.
4) Elige el driver de repositorio de clientes (`config` o `eloquent`).
5) Si usas `eloquent`, crea tablas `api_apps` + `api_app_keys` (o `api_clients` legacy).
6) Aplica el middleware en el orden correcto (ver Referencia de Middleware + Ejemplos por Canal).
7) Asegura que el login solo use `app.context` + rate limit y emita JWT con `aud` correcto.
8) Ejecuta `app.binding` después de JWT para validar audiencia/tenant.
9) Valida headers de API key (`X-Client-Id`, `X-Api-Key`) para B2B.
10) Verifica rate limits y auditoría en `config/app-context.php`.

## 3) Instalación

### Composer

```bash
composer require ronu/laravel-app-context
```

### Publicar configuración

```bash
php artisan vendor:publish --tag=app-context-config
```

### Auto-descubrimiento del Service Provider

Laravel auto-registra el provider vía `composer.json`. Si lo deshabilitas, agrégalo en tu app:

```php
// config/app.php
'providers' => [
    Ronu\AppContext\AppContextServiceProvider::class,
],
```

## 4) Arquitectura del paquete (diagrama Mermaid)

**Flujo de petición**

```mermaid
flowchart TD
    A[Solicitud Entrante] --> B[ResolveAppContext (host/path)]
    B --> C{Modo Auth}
    C -->|jwt| D[AuthenticateChannel: JWT]
    C -->|api_key| E[AuthenticateChannel: API Key]
    C -->|anonymous| F[AuthenticateChannel: Anonymous]
    D --> G[EnforceContextBinding]
    E --> G[EnforceContextBinding]
    F --> G[EnforceContextBinding]
    G --> H[RateLimitByContext]
    H --> I[InjectAuditContext]
    I --> J[RequireScope (por ruta)]
    J --> K[Controlador / Lógica]
```

## 5) Referencia de Middleware

> Los alias y el grupo `app-context` se registran en `Ronu\AppContext\AppContextServiceProvider` usando `Router::aliasMiddleware()` y `middlewareGroup()`.

| Middleware | Propósito | Dónde registrar | Orden | Aplica a |
|---|---|---|---|---|
| `app.context` | Resuelve canal + contexto base | Grupo de rutas (o `app-context`) | 1 | dashboard, mobile, b2b |
| `app.auth` | Autentica por canal (`jwt`, `api_key`, `anonymous`) | Grupo de rutas | 2 | dashboard, mobile, b2b |
| `app.binding` | Enforce de audiencia/tenant | Grupo de rutas | 3 | dashboard, mobile, b2b |
| `app.throttle` | Rate limit por contexto | Grupo de rutas | 4 | dashboard, mobile, b2b |
| `app.audit` | Inyecta contexto en logs | Grupo de rutas | 5 | dashboard, mobile, b2b |
| `app.scope` | Exige scopes/capabilities (OR) | Por ruta | Después de auth/binding | dashboard, mobile, b2b |

**Nota:** Existe `Ronu\AppContext\Middleware\RequireAllScopes`, pero no está aliasado por el provider. Si lo necesitas, regístralo (ver abajo).

### Opcional: alias para `RequireAllScopes` (lógica AND)

**Laravel 11/12 (`bootstrap/app.php`)**

```php
// bootstrap/app.php
->withMiddleware(function (Illuminate\Foundation\Configuration\Middleware $middleware) {
    $middleware->alias([
        'app.scope.all' => Ronu\AppContext\Middleware\RequireAllScopes::class,
    ]);
})
```

**Legacy (`app/Http/Kernel.php`)**

```php
// app/Http/Kernel.php
protected $routeMiddleware = [
    'app.scope.all' => Ronu\AppContext\Middleware\RequireAllScopes::class,
];
```

## 6) Configuración

Archivo: `config/app-context.php`.

### Claves principales

| Clave | Descripción | Default / Ejemplo |
|---|---|---|
| `client_repository.driver` | Backend (`config`, `eloquent` o clase custom) | `config` |
| `deny_by_default` | Bloquear si no hay match de canal | `true` |
| `default_channel` | Canal por defecto si no se bloquea | `default` |
| `domain` | Dominio base para subdominios | `APP_CONTEXT_DOMAIN` |
| `detection_strategy` | `auto`, `path`, `subdomain`, `strict` | `auto` |
| `auto_detection_rules` | Host → estrategia | ver archivo |
| `app_context_dev` | Envs que usan path por defecto | `local` |
| `channels` | Definición de canales | ver archivo |
| `rate_limits` | Profiles de rate limit | ver archivo |
| `jwt` | Verificación + fallback JWT | ver archivo |
| `api_key` | Headers, rotación y formato | ver archivo |
| `security` | Toggles de seguridad | ver archivo |
| `audit` | Logging | ver archivo |
| `public_routes` | Rutas públicas | ver archivo |

### Definición de canales (clave de seguridad)

Cada canal define:
- **`auth_mode`**: `jwt`, `api_key`, `anonymous`, `jwt_or_anonymous`.
- **`jwt_audience`**: `aud` esperado para JWT.
- **`allowed_scopes`** / **`allowed_capabilities`**: allow-list.
- **`tenant_mode`**: `single` o `multi`.

### Headers de API Key

Headers por defecto (configurable en `api_key.headers`):
- `X-Client-Id` → identificador (`app_code`)
- `X-Api-Key` → API key (`prefix.secret`)

### Configuración JWT para proxy inverso

Cuando tu aplicación está detrás de un proxy inverso (nginx, HAProxy, etc.) que termina SSL, el protocolo puede cambiar de `https` a `http` internamente. Esto causa que la validación del issuer falle porque las URLs no coinciden exactamente.

| Variable de entorno | Descripción | Default |
|---|---|---|
| `JWT_IGNORE_ISSUER_SCHEME` | Ignora el protocolo (http/https) al validar el issuer | `false` |

**Ejemplo de uso:**

```env
# .env
JWT_ISSUER=https://api.tumerkado.com
JWT_IGNORE_ISSUER_SCHEME=true
```

Con esta configuración, las siguientes URLs serán consideradas equivalentes:
- `https://api.tumerkado.com/admin/login`
- `http://api.tumerkado.com/admin/login`

### Defaults seguros

Defaults recomendados ya presentes:
- `deny_by_default = true`
- `security.strict_algorithm_check = true`
- `jwt.verify_aud = true` y `jwt.verify_iss = true`
- `api_key.hash_algorithm = argon2id`
- `security.enforce_tenant_binding = true`

## 7) Autenticación (JWT con php-open-source-saver/jwt-auth)

### Cambios en controlador (login/logout/refresh)

> El paquete **no** incluye AuthController. Si tu app ya lo tiene, conserva tus endpoints y agrega el binding de claims.

**Dónde ponerlo:** `app/Http/Controllers/AuthController.php`.

#### Login (JWT: bind de app context)

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Ronu\AppContext\Context\AppContext;

public function login(Request $request, AppContext $context)
{
    $credentials = $request->only(['email', 'password']);

    if (! $token = Auth::attempt($credentials)) {
        return response()->json(['message' => 'Credenciales inválidas'], 401);
    }

    $claims = [
        'aud' => $context->getAppId(),
        'tid' => $request->header('X-Tenant-Id') ?? $request->route('tenant_id') ?? $request->query('tenant_id'),
        'scp' => [],
    ];

    $token = JWTAuth::claims($claims)->fromUser(Auth::user());

    return response()->json([
        'access_token' => $token,
        'token_type' => 'Bearer',
        'expires_in' => config('app-context.jwt.ttl'),
        'audience' => $context->getAppId(),
        'tenant_id' => $claims['tid'],
    ]);
}
```

#### Logout (invalida token)

```php
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

public function logout()
{
    JWTAuth::invalidate(JWTAuth::getToken());

    return response()->json(['message' => 'Sesión cerrada']);
}
```

#### Refresh (refrescar token)

```php
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

public function refresh()
{
    $newToken = JWTAuth::refresh(JWTAuth::getToken());

    return response()->json([
        'access_token' => $newToken,
        'token_type' => 'Bearer',
        'expires_in' => config('app-context.jwt.ttl'),
    ]);
}
```

### Ejemplos de rutas

**Grupo de login** (sin `app.auth`):

```php
// routes/api.php
Route::middleware([
    'app.context',
    'app.binding',
    'app.throttle',
    'app.audit',
])->post('/api/login', [AuthController::class, 'login']);
```

**Grupo autenticado**:

```php
Route::middleware([
    'app.context',
    'app.auth',
    'app.binding',
    'app.throttle',
    'app.audit',
])->group(function () {
    Route::get('/api/me', [AuthController::class, 'me']);
});
```

### Binding de claims en JWT (recomendado)

Incluye al menos:
- `aud`: canal (ej. `admin`, `mobile`, `site`)
- `tid`: tenant (si aplica)
- `scp`: scopes (si aplica)

`app.binding` valida `aud` y `tid`.

## 8) Ejemplos por canal

### dashboard (web client / SPA)

**Canal esperado**: `admin` (JWT)

```php
// routes/api.php
Route::prefix('api')->middleware([
    'app.context',
    'app.auth',
    'app.binding',
    'app.throttle',
    'app.audit',
])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index'])
        ->middleware('app.scope:admin:dashboard:read');
});
```

### mobile

**Canal esperado**: `mobile` (JWT)

```php
// routes/api.php
Route::prefix('mobile')->middleware([
    'app.context',
    'app.auth',
    'app.binding',
    'app.throttle',
    'app.audit',
])->group(function () {
    Route::get('/orders', [OrderController::class, 'index'])
        ->middleware('app.scope:mobile:orders:read');
});
```

### b2b

**Canal esperado**: `partner` (API key)

```php
// routes/api.php
Route::prefix('partner')->middleware([
    'app.context',
    'app.auth',
    'app.binding',
    'app.throttle',
    'app.audit',
])->group(function () {
    Route::get('/inventory', [PartnerInventoryController::class, 'index'])
        ->middleware('app.scope:partner:inventory:read');
});
```

## 9) Solución de problemas

- **"AppContext not resolved"** → Asegura que `app.context` es el primero.
- **JWT audience mismatch** → El login debe emitir tokens con `aud` correcto.
- **JWT issuer mismatch con proxy inverso** → Si usas un proxy inverso que cambia el protocolo (ej. nginx con SSL termination), el issuer del token (`https://`) puede no coincidir con la URL interna (`http://`). Solución: configura `JWT_IGNORE_ISSUER_SCHEME=true` en tu `.env`.
- **Errores de tenant** → Enviar `tenant_id` por ruta, query o header `X-Tenant-Id`.
- **API key inválida** → Verifica `X-Client-Id` + `X-Api-Key` y hash.

## 10) Checklist de seguridad

- [ ] `deny_by_default = true` en producción.
- [ ] `jwt.verify_aud = true` y `jwt.verify_iss = true`.
- [ ] Tokens incluyen `aud` y `tid`.
- [ ] API keys hasheadas con Argon2id/Bcrypt.
- [ ] IP allowlist en partners críticos.
- [ ] Auditoría de fallos de auth.
- [ ] Rate limits por canal/endpoint.

## 11) Notas de changelog (breaking changes / upgrade tips)

N/A (no se encontró changelog en el repo).
