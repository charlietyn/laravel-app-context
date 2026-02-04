# Security

## Resumen
El paquete implementa controles de seguridad en varios puntos: verificación estricta de JWT (algoritmo, issuer, audience, blacklist), validación de API keys (hash, expiración, revocación, IP allowlist) y binding de tenant/canal.

## Controles clave
### 1) JWT hardening
- Rechazo de algoritmo `none` y whitelist de algoritmos.
- Validación de `aud` y `iss`.
- Blacklist opcional con cache.

### 2) API Key hardening
- Hash `argon2id` (recomendado).
- Expiración y revocación.
- IP allowlist opcional (y forzado si `enforce_ip_allowlist=true`).

### 3) Context binding
- `aud` debe coincidir con el canal.
- `tenant_id` debe coincidir con el request cuando `tenant_mode=multi`.

### 4) Audit logging
- `InjectAuditContext` añade metadata en logs y permite redacción de headers sensibles.

## Pitfalls comunes
- `JWT_IGNORE_ISSUER_SCHEME` debe habilitarse detrás de reverse proxies si cambian `http/https`.
- Si `anonymous_on_invalid_token=false`, un JWT inválido en `jwt_or_anonymous` rechaza la petición.
- Si `enforce_ip_allowlist=true` y el allowlist está vacío, el request fallará.

## Checklist recomendado
- [ ] `deny_by_default=true`
- [ ] `jwt.verify_aud=true`, `jwt.verify_iss=true`
- [ ] `jwt.allowed_algorithms` sin `none`
- [ ] `security.enforce_tenant_binding=true`
- [ ] `api_key.hash_algorithm=argon2id`
- [ ] `audit.log_failed_auth=true`

## Evidence
- File: src/Auth/Verifiers/JwtVerifier.php
  - Symbol: JwtVerifier::preVerify(), JwtVerifier::postVerify()
  - Notes: validación de algoritmos, issuer/audience y blacklist.
- File: src/Auth/Verifiers/ApiKeyVerifier.php
  - Symbol: ApiKeyVerifier::verify(), ApiKeyVerifier::isIpAllowed()
  - Notes: hash, revocación, expiración, allowlist.
- File: src/Middleware/EnforceContextBinding.php
  - Symbol: EnforceContextBinding::validateJwtBinding(), EnforceContextBinding::validateTenantBinding()
  - Notes: binding de canal y tenant.
- File: src/Middleware/InjectAuditContext.php
  - Symbol: InjectAuditContext::filterHeaders()
  - Notes: redacción de headers sensibles.
- File: config/app-context.php
  - Symbol: jwt, api_key, security, audit
  - Notes: configuración de seguridad.
