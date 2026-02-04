# Laravel App Context (ronu/laravel-app-context)

## ¿Qué es y qué resuelve?
Laravel App Context es un paquete que resuelve **contexto de aplicación por canal** (mobile, admin, site, partner) y centraliza autenticación (JWT o API Key), autorización (scopes/capabilities), rate limiting por contexto y auditoría de solicitudes. Todo gira alrededor de un objeto inmutable `AppContext` que se inyecta en el request y en el contenedor para que el resto de la app pueda tomar decisiones consistentes por canal, tenant y credencial. 

## Quickstart (mínimo viable)
> Objetivo: canal `mobile` con JWT y middleware completo.

1) Instala el paquete:
```bash
composer require ronu/laravel-app-context
```

2) Publica la configuración:
```bash
php artisan vendor:publish --tag=app-context-config
```

3) Define un canal (ejemplo `mobile`) en `config/app-context.php`:
```php
'channels' => [
    'mobile' => [
        'subdomains' => ['mobile', 'm'],
        'path_prefixes' => ['/mobile'],
        'auth_mode' => 'jwt',
        'jwt_audience' => 'mobile',
        'allowed_scopes' => ['mobile:*', 'user:profile:*'],
        'rate_limit_profile' => 'mobile',
        'tenant_mode' => 'multi',
    ],
],
```

4) Crea rutas con el middleware group `app-context`:
```php
// routes/api.php
Route::prefix('mobile')
    ->middleware(['app-context'])
    ->group(function () {
        Route::get('/profile', [UserController::class, 'profile'])
            ->middleware('app.requires:user:profile:read');
    });
```

5) En tu login, emite JWT con `aud` y `scp` coherentes con el canal:
```php
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Ronu\AppContext\Context\AppContext;

public function login(Request $request, AppContext $context)
{
    // ... validar credenciales ...
    $claims = [
        'aud' => $context->getAppId(),
        'tid' => $request->header('X-Tenant-Id'),
        'scp' => ['mobile:*', 'user:profile:read'],
    ];

    $token = JWTAuth::claims($claims)->fromUser(Auth::user());

    return response()->json([
        'access_token' => $token,
        'token_type' => 'Bearer',
        'expires_in' => config('app-context.jwt.ttl'),
    ]);
}
```

6) Asegura que `app.binding` corre después de auth (en group o manual).

## Índice
- [Instalación](docs/01-installation.md)
- [Configuración](docs/02-configuration.md)
- [Arquitectura](docs/03-architecture.md)
- [Features](docs/04-features/)
- [Seguridad](docs/05-security.md)
- [Testing](docs/06-testing.md)
- [Troubleshooting](docs/07-troubleshooting.md)
- [FAQ](docs/08-faq.md)
- [Reference](docs/09-reference/)
- [Migration guide](docs/10-migration-guide.md)
- [Contributing](docs/11-contributing.md)
- [License](docs/12-license.md)

## Requisitos
- PHP ^8.2
- Laravel 11 o 12 (paquetes Illuminate)
- `php-open-source-saver/jwt-auth` ^2.0

## Common integration paths
- **API multi-canal**: usa `app-context` group en rutas `/admin`, `/mobile`, `/partner` y define canales por `path_prefixes` o `subdomains`.
- **B2B partners**: usa `auth_mode=api_key` con headers `X-Client-Id` y `X-Api-Key`.
- **Public web + opcional JWT**: usa `auth_mode=jwt_or_anonymous` para permitir navegación pública y personalización si hay token.

## Evidence
- File: composer.json
  - Symbol: name, require
  - Notes: nombre del paquete y versiones mínimas de PHP/Laravel/JWT.
- File: src/AppContextServiceProvider.php
  - Symbol: AppContextServiceProvider::register(), AppContextServiceProvider::boot()
  - Notes: auto-registro de middleware, provider y comandos.
- File: config/app-context.php
  - Symbol: channels, jwt, api_key, rate_limits
  - Notes: configuración principal del paquete.
- File: src/Middleware/AuthenticateChannel.php
  - Symbol: AuthenticateChannel::handle()
  - Notes: autenticación por canal.
- File: src/Middleware/EnforceContextBinding.php
  - Symbol: EnforceContextBinding::handle()
  - Notes: binding de audience/tenant.
