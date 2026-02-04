# 02-config-matrix

| Config key path | Declared in | Used in | Suggested action | Evidence |
| --- | --- | --- | --- | --- |
| app-context.client_repository.driver | config/app-context.php | AppContextServiceProvider | KEEP | Driver selecciona repositorio en `AppContextServiceProvider`.
| app-context.client_repository.config.clients | config/app-context.php | ConfigClientRepository | KEEP | Repositorio config consume `clients`.
| app-context.client_repository.config.hash_algorithm | config/app-context.php | ConfigClientRepository | KEEP | Se lee en constructor.
| app-context.client_repository.config.prefix_length | config/app-context.php | ConfigClientRepository | KEEP | Se usa en constructor.
| app-context.client_repository.config.key_length | config/app-context.php | ConfigClientRepository | KEEP | Se usa en constructor.
| app-context.client_repository.eloquent.table | config/app-context.php | EloquentClientRepository | KEEP | Se lee en constructor.
| app-context.client_repository.eloquent.apps_table | config/app-context.php | EloquentClientRepository | KEEP | Se lee en constructor.
| app-context.client_repository.eloquent.app_keys_table | config/app-context.php | EloquentClientRepository | KEEP | Se lee en constructor.
| app-context.client_repository.eloquent.app_model | config/app-context.php | EloquentClientRepository | KEEP | Se lee en constructor.
| app-context.client_repository.eloquent.app_key_model | config/app-context.php | EloquentClientRepository | KEEP | Se lee en constructor.
| app-context.client_repository.eloquent.connection | config/app-context.php | EloquentClientRepository | KEEP | Se lee en constructor.
| app-context.client_repository.eloquent.hash_algorithm | config/app-context.php | EloquentClientRepository | KEEP | Se lee en constructor.
| app-context.client_repository.eloquent.prefix_length | config/app-context.php | EloquentClientRepository | KEEP | Se lee en constructor.
| app-context.client_repository.eloquent.key_length | config/app-context.php | EloquentClientRepository | KEEP | Se lee en constructor.
| app-context.client_repository.eloquent.async_tracking | config/app-context.php | EloquentClientRepository | KEEP | Se lee en constructor.
| app-context.deny_by_default | config/app-context.php | ContextResolver | KEEP | Se evalúa en resolución de contexto.
| app-context.default_channel | config/app-context.php | ResolveAppContext middleware | KEEP | Se usa en fallback.
| app-context.domain | config/app-context.php | ContextResolver | KEEP | Se usa para subdominio.
| app-context.detection_strategy | config/app-context.php | ContextResolver | KEEP | Determina estrategia.
| app-context.auto_detection_rules | config/app-context.php | ContextResolver | KEEP | Reglas auto.
| app-context.app_context_dev | config/app-context.php | ContextResolver / AppContextServiceProvider | KEEP | Usa lista de entornos.
| app-context.channels.*.subdomains | config/app-context.php | ContextResolver | KEEP | Subdominios válidos.
| app-context.channels.*.path_prefixes | config/app-context.php | ContextResolver | KEEP | Prefijos de ruta.
| app-context.channels.*.auth_mode | config/app-context.php | ContextResolver + Authenticators | KEEP | Modo auth.
| app-context.channels.*.jwt_audience | config/app-context.php | EnforceContextBinding | KEEP | Se valida audience.
| app-context.channels.*.allowed_scopes | config/app-context.php | JwtAuthenticator / PublicScopeResolver | KEEP | Scopes permitidos.
| app-context.channels.*.public_scopes | config/app-context.php | PublicScopeResolver | KEEP | Scopes públicos.
| app-context.channels.*.allowed_capabilities | config/app-context.php | ApiKeyAuthenticator | KEEP | Capabilities.
| app-context.channels.*.anonymous_on_invalid_token | config/app-context.php | JwtAuthenticator | KEEP | Fallback anónimo.
| app-context.channels.*.rate_limit_profile | config/app-context.php | RateLimitByContext | KEEP | Selección de perfil.
| app-context.channels.*.tenant_mode | config/app-context.php | EnforceContextBinding | KEEP | Modo tenant.
| app-context.channels.*.features.allow_anonymous | config/app-context.php | JwtAuthenticator / Facade | KEEP | Usado para permisos.
| app-context.channels.*.audit.enabled | config/app-context.php | InjectAuditContext | KEEP | Overrides por canal.
| app-context.channels.*.audit.log_all_requests | config/app-context.php | InjectAuditContext | KEEP | Overrides por canal.
| app-context.rate_limits.*.global | config/app-context.php | RateLimitByContext | KEEP | Límite global.
| app-context.rate_limits.*.authenticated_global | config/app-context.php | RateLimitByContext | KEEP | Límite auth.
| app-context.rate_limits.*.by | config/app-context.php | RateLimitByContext | KEEP | Clave de rate.
| app-context.rate_limits.*.burst | config/app-context.php | RateLimitByContext | KEEP | Burst.
| app-context.rate_limits.*.endpoints | config/app-context.php | RateLimitByContext | KEEP | Limites por endpoint.
| app-context.jwt.algorithm | config/app-context.php | AppContextServiceProvider | KEEP | Se usa para fallback.
| app-context.jwt.public_key_path | config/app-context.php | AppContextServiceProvider | KEEP | Detecta claves RSA.
| app-context.jwt.private_key_path | config/app-context.php | AppContextServiceProvider | KEEP | Detecta claves RSA.
| app-context.jwt.issuer | config/app-context.php | JwtVerifier | KEEP | Validación issuer.
| app-context.jwt.ttl | config/app-context.php | — | INVESTIGATE | No hay lectura en runtime del paquete.
| app-context.jwt.refresh_ttl | config/app-context.php | JwtVerifier | KEEP | Usado en refresh.
| app-context.jwt.blacklist_enabled | config/app-context.php | JwtVerifier | KEEP | Usa blacklist.
| app-context.jwt.blacklist_grace_period | config/app-context.php | — | INVESTIGATE | Sin callsites en paquete.
| app-context.jwt.verify_iss | config/app-context.php | JwtVerifier | KEEP | Validación issuer.
| app-context.jwt.ignore_issuer_scheme | config/app-context.php | JwtVerifier | KEEP | Validación issuer.
| app-context.jwt.verify_aud | config/app-context.php | EnforceContextBinding / JwtVerifier | KEEP | Validación audience.
| app-context.jwt.allowed_algorithms | config/app-context.php | JwtVerifier | KEEP | Whitelist.
| app-context.jwt.token_sources | config/app-context.php | JwtVerifier | KEEP | Extracción de token.
| app-context.jwt.dev_fallback.enabled | config/app-context.php | AppContextServiceProvider | KEEP | Fallback en dev.
| app-context.jwt.dev_fallback.algorithm | config/app-context.php | AppContextServiceProvider | KEEP | Fallback HS/RS.
| app-context.jwt.dev_fallback.secret | config/app-context.php | AppContextServiceProvider | KEEP | Secret fallback.
| app-context.api_key.hash_algorithm | config/app-context.php | ApiKeyVerifier | KEEP | Algoritmo hash.
| app-context.api_key.headers.client_id | config/app-context.php | ApiKeyVerifier | KEEP | Header client id.
| app-context.api_key.headers.api_key | config/app-context.php | ApiKeyVerifier | KEEP | Header api key.
| app-context.api_key.rotation_days | config/app-context.php | — | INVESTIGATE | No hay callsites en paquete.
| app-context.api_key.expiration_warning_days | config/app-context.php | — | INVESTIGATE | No hay callsites en paquete.
| app-context.api_key.max_keys_per_client | config/app-context.php | — | INVESTIGATE | No hay callsites en paquete.
| app-context.api_key.prefix_length | config/app-context.php | Config/EloquentClientRepository | KEEP | Se usa por repositorios.
| app-context.api_key.key_length | config/app-context.php | Config/EloquentClientRepository | KEEP | Se usa por repositorios.
| app-context.security.strict_algorithm_check | config/app-context.php | — | INVESTIGATE | No hay callsites en paquete.
| app-context.security.enforce_tenant_binding | config/app-context.php | EnforceContextBinding | KEEP | Control seguridad.
| app-context.security.enforce_ip_allowlist | config/app-context.php | ApiKeyVerifier | KEEP | Control seguridad.
| app-context.security.anomaly_detection.enabled | config/app-context.php | — | INVESTIGATE | Sin callsites en paquete.
| app-context.security.anomaly_detection.max_ip_changes_per_hour | config/app-context.php | — | INVESTIGATE | Sin callsites en paquete.
| app-context.security.anomaly_detection.max_device_changes_per_day | config/app-context.php | — | INVESTIGATE | Sin callsites en paquete.
| app-context.audit.enabled | config/app-context.php | InjectAuditContext | KEEP | Control audit.
| app-context.audit.log_channel | config/app-context.php | InjectAuditContext | KEEP | Canal log.
| app-context.audit.include_request_body | config/app-context.php | InjectAuditContext | KEEP | Incluye body.
| app-context.audit.include_response_body | config/app-context.php | InjectAuditContext | KEEP | Incluye body.
| app-context.audit.log_all_requests | config/app-context.php | InjectAuditContext | KEEP | Log all.
| app-context.audit.log_responses | config/app-context.php | InjectAuditContext | KEEP | Log responses.
| app-context.audit.log_failed_auth | config/app-context.php | AuthenticateChannel | KEEP | Log fallo auth.
| app-context.audit.sensitive_headers | config/app-context.php | InjectAuditContext | KEEP | Redacción headers.
| app-context.public_routes.names | config/app-context.php | JwtAuthenticator | KEEP | Rutas públicas.
| app-context.public_routes.name_endings | config/app-context.php | JwtAuthenticator | KEEP | Rutas públicas.
| app-context.public_routes.path_endings | config/app-context.php | JwtAuthenticator | KEEP | Rutas públicas.

**Notas:**
- Marcados como **INVESTIGATE** requieren confirmación manual antes de eliminar/modificar (pueden ser usados por consumidores o en versiones futuras).

