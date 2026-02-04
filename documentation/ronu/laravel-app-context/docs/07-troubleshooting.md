# Troubleshooting

## Problemas comunes
### 1) “Request does not match any configured channel”
Causa: `deny_by_default=true` y no hay canal para host/path.
Solución: revisa `channels` y `domain`/`detection_strategy`.

### 2) “Token audience mismatch”
Causa: `aud` no coincide con el canal.
Solución: emite tokens con `aud = AppContext::getAppId()`.

### 3) “Tenant mismatch / missing tenant”
Causa: `tenant_mode=multi` y el token no tiene `tid` o no coincide con el request.
Solución: incluir `tid` en claims y enviar `tenant_id` por ruta/header/query.

### 4) “API key required”
Causa: headers faltantes (`X-Client-Id`, `X-Api-Key`).

## Discrepancias con docs existentes
- `docs/Documentation.md` menciona comandos `app-context:generate-key`, `app-context:list-clients`, `app-context:revoke-key` como “planned”, pero **el único comando implementado** es `route:channel`.

## Evidence
- File: src/Exceptions/ContextBindingException.php
  - Symbol: ContextBindingException::denyByDefault(), ContextBindingException::audienceMismatch(), ContextBindingException::missingTenant(), ContextBindingException::tenantMismatch()
  - Notes: errores frecuentes de binding.
- File: src/Exceptions/AuthenticationException.php
  - Symbol: AuthenticationException::missingApiKey()
  - Notes: error típico cuando faltan headers de API key.
- File: src/Commands/RoutesByChannel.php
  - Symbol: RoutesByChannel
  - Notes: único comando real en el paquete.
- File: docs/Documentation.md
  - Symbol: “Artisan Commands” section
  - Notes: lista de comandos planificados no implementados.
