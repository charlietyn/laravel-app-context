# Optional Anonymous Access (jwt_or_anonymous)

## Overview
Permite rutas públicas con **auth opcional**: si hay token, lo valida; si no hay (o si el canal permite fallback), crea un `AppContext` anónimo con scopes públicos.

## When to use / When NOT to use
**Úsalo cuando:**
- Tienes catálogo público con personalización para usuarios autenticados.
- Quieres permitir navegación sin token, pero aprovechar scopes si existen.

**Evítalo cuando:**
- Necesitas seguridad estricta; usa `jwt` y elimina fallback.

## How it works
- `JwtAuthenticator` detecta si la ruta es pública o si el canal permite `allow_anonymous`.
- En `jwt_or_anonymous`, usa `tryAuthenticate()` y crea contexto anónimo con `PublicScopeResolver` si no hay token.

## Configuration
Keys relevantes:
- `channels.<channel>.auth_mode = jwt_or_anonymous`
- `channels.<channel>.public_scopes`
- `channels.<channel>.anonymous_on_invalid_token`
- `channels.<channel>.features.allow_anonymous`
- `public_routes.*`

## Usage examples
```php
// config/app-context.php
'site' => [
    'auth_mode' => 'jwt_or_anonymous',
    'public_scopes' => ['catalog:browse', 'public:read'],
    'anonymous_on_invalid_token' => false,
],
```

```php
public function catalog(AppContext $context)
{
    if ($context->isAuthenticated()) {
        return $this->personalizedCatalog($context->getUserId());
    }

    return $this->publicCatalog();
}
```

## Edge cases / pitfalls
- Si `anonymous_on_invalid_token=false`, un token inválido **bloquea** el request.
- Si `public_scopes` está vacío, el resolver usa scopes seguros por defecto (`public:read`, `catalog:browse`).

## Evidence
- File: src/Auth/Authenticators/JwtAuthenticator.php
  - Symbol: JwtAuthenticator::tryAuthenticate(), JwtAuthenticator::buildAnonymousContext(), JwtAuthenticator::shouldFallbackOnInvalidToken()
  - Notes: fallback a contexto anónimo y reglas de invalid token.
- File: src/Support/PublicScopeResolver.php
  - Symbol: PublicScopeResolver::resolve()
  - Notes: scopes públicos por canal.
- File: config/app-context.php
  - Symbol: channels.*.auth_mode, channels.*.public_scopes, channels.*.anonymous_on_invalid_token, public_routes
  - Notes: configuración para auth opcional.

## Related docs
- [Configuration](../02-configuration.md)
- [Security](../05-security.md)
