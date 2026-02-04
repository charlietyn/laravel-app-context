# JWT Authentication

## Overview
Autentica usuarios con JWT, valida firma, algoritmo permitido, issuer y audience. Construye el `AppContext` con `userId`, `tenantId`, `scopes` y metadata de claims.

## When to use / When NOT to use
**Úsalo cuando:**
- Necesitas auth basada en tokens para canales `jwt`.
- Quieres scopes por usuario y validación de issuer/audience.

**Evítalo cuando:**
- El canal sea exclusivamente M2M (usa `api_key`).

## How it works
- `JwtVerifier` extrae token de header/query/cookie según `token_sources`.
- `preVerify` valida estructura y algoritmo (rechaza `none`).
- `postVerify` valida `aud`, `iss`, `sub` y blacklist.
- `JwtAuthenticator` carga usuario (`Auth::getProvider()`), resuelve scopes y crea `AppContext`.

## Configuration
Keys relevantes:
- `jwt.algorithm`, `jwt.allowed_algorithms`
- `jwt.issuer`, `jwt.verify_iss`, `jwt.ignore_issuer_scheme`
- `jwt.verify_aud`
- `jwt.token_sources`
- `jwt.blacklist_enabled`

## Usage examples
```php
// routes/api.php
Route::middleware(['app.context', 'app.auth', 'app.binding'])
    ->get('/api/me', [MeController::class, 'show'])
    ->middleware('app.requires:admin:users:read');
```

```php
// Emisión de token con claims mínimos
$claims = [
    'aud' => $context->getAppId(),
    'tid' => $request->header('X-Tenant-Id'),
    'scp' => ['admin:*'],
];

$token = JWTAuth::claims($claims)->fromUser($user);
```

## Edge cases / pitfalls
- `JWT_IGNORE_ISSUER_SCHEME` es útil detrás de reverse proxy.
- Si falta `aud` y `verify_aud=true`, se rechaza el token.
- Si falta `sub`, el token se considera inválido.

## Evidence
- File: src/Auth/Verifiers/JwtVerifier.php
  - Symbol: JwtVerifier::verify(), JwtVerifier::preVerify(), JwtVerifier::postVerify()
  - Notes: validaciones JWT y manejo de blacklist/issuer/audience.
- File: src/Auth/Authenticators/JwtAuthenticator.php
  - Symbol: JwtAuthenticator::authenticate(), JwtAuthenticator::authenticateWithToken()
  - Notes: carga de usuario y construcción de scopes.
- File: config/app-context.php
  - Symbol: jwt
  - Notes: configuración JWT.

## Related docs
- [Security](../05-security.md)
- [Reference: config keys](../09-reference/config-keys.md)
