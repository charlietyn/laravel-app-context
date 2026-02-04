# API Key Authentication

## Overview
Autentica integraciones B2B/M2M con headers `X-Client-Id` y `X-Api-Key`. Valida hash, expiración, revocación e IP allowlist (opcional) y construye `AppContext` con `clientId`, `capabilities` y metadata.

## When to use / When NOT to use
**Úsalo cuando:**
- El canal es de partners externos sin usuarios finales.
- Necesitas capabilities por cliente.

**Evítalo cuando:**
- El canal requiere identidad de usuario (usa `jwt`).

## How it works
- `ApiKeyVerifier` extrae headers y busca el cliente vía `ClientRepositoryInterface`.
- Verifica hash, revocación y expiración; aplica IP allowlist.
- `ApiKeyAuthenticator` filtra capabilities contra `allowed_capabilities` del canal.

## Configuration
Keys relevantes:
- `api_key.headers.client_id` / `api_key.headers.api_key`
- `api_key.hash_algorithm`
- `security.enforce_ip_allowlist`
- `client_repository.*`

## Usage examples
```php
// routes/api.php
Route::prefix('partner')
    ->middleware(['app.context', 'app.auth', 'app.binding'])
    ->group(function () {
        Route::get('/inventory', [InventoryController::class, 'index'])
            ->middleware('app.requires:partner:inventory:read');
    });
```

```bash
curl -H "X-Client-Id: acme" \
     -H "X-Api-Key: prefix.secret" \
     https://api.example.com/partner/inventory
```

## Edge cases / pitfalls
- Si `enforce_ip_allowlist=true` y el allowlist está vacío, el request se rechaza.
- En repo `config`, `create()` y `revoke()` no están soportados (runtime exception).

## Evidence
- File: src/Auth/Verifiers/ApiKeyVerifier.php
  - Symbol: ApiKeyVerifier::verify(), ApiKeyVerifier::isIpAllowed()
  - Notes: validación de credenciales e IP allowlist.
- File: src/Auth/Authenticators/ApiKeyAuthenticator.php
  - Symbol: ApiKeyAuthenticator::authenticate(), ApiKeyAuthenticator::buildCapabilities()
  - Notes: filtro de capabilities por canal.
- File: src/Repositories/ConfigClientRepository.php
  - Symbol: ConfigClientRepository::create(), ConfigClientRepository::revoke()
  - Notes: operaciones no soportadas en driver config.
- File: config/app-context.php
  - Symbol: api_key, security.enforce_ip_allowlist, client_repository
  - Notes: configuración para API keys y repositorios.

## Related docs
- [Configuration](../02-configuration.md)
- [Security](../05-security.md)
