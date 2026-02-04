# Environment Variables

Variables leídas por `config/app-context.php`.

| Env var | Descripción |
| --- | --- |
| `APP_CONTEXT_CLIENT_DRIVER` | Driver de clientes (`config`/`eloquent`). |
| `API_KEY_HASH_ALGO` | Hash para API keys. |
| `APP_CONTEXT_CLIENTS_TABLE` | Tabla legacy `api_clients`. |
| `APP_CONTEXT_APPS_TABLE` | Tabla `api_apps`. |
| `APP_CONTEXT_APP_KEYS_TABLE` | Tabla `api_app_keys`. |
| `APP_CONTEXT_APP_MODEL` | Modelo Eloquent custom (apps). |
| `APP_CONTEXT_APP_KEY_MODEL` | Modelo Eloquent custom (keys). |
| `APP_CONTEXT_CLIENTS_CONNECTION` | Conexión DB para clientes. |
| `APP_CONTEXT_DENY_BY_DEFAULT` | Toggle `deny_by_default`. |
| `APP_CONTEXT_DEFAULT_CHANNEL` | Canal default. |
| `APP_CONTEXT_DOMAIN` | Dominio base. |
| `APP_DOMAIN` | Fallback para dominio base. |
| `APP_CONTEXT_DETECTION` | Estrategia de detección. |
| `APP_CONTEXT_DEV` | Envs que usan path en auto-detection. |
| `ADMIN_MFA_REQUIRED` | Flag de ejemplo en canal admin. |
| `RATE_LIMIT_MOBILE_GLOBAL` | Límite global móvil. |
| `RATE_LIMIT_ADMIN_GLOBAL` | Límite global admin. |
| `RATE_LIMIT_SITE_ANON` | Límite anónimo site. |
| `RATE_LIMIT_SITE_AUTH` | Límite autenticado site. |
| `RATE_LIMIT_PARTNER_GLOBAL` | Límite global partner. |
| `JWT_ALGO` | Algoritmo JWT. |
| `JWT_PUBLIC_KEY_PATH` | Ruta clave pública. |
| `JWT_PRIVATE_KEY_PATH` | Ruta clave privada. |
| `JWT_ISSUER` | Issuer esperado. |
| `JWT_TTL` | TTL del token. |
| `JWT_REFRESH_TTL` | TTL de refresh. |
| `JWT_BLACKLIST_ENABLED` | Blacklist habilitada. |
| `JWT_VERIFY_ISS` | Validar issuer. |
| `JWT_IGNORE_ISSUER_SCHEME` | Ignorar esquema http/https. |
| `JWT_VERIFY_AUD` | Validar audiencia. |
| `JWT_TOKEN_SOURCES` | Fuentes de token. |
| `JWT_DEV_FALLBACK` | Fallback dev. |
| `JWT_DEV_ALGO` | Algoritmo de fallback. |
| `JWT_DEV_SECRET` | Secret de fallback. |
| `API_KEY_CLIENT_ID_HEADER` | Header client ID. |
| `API_KEY_HEADER` | Header API key. |
| `API_KEY_ROTATION_DAYS` | Días de rotación. |
| `API_KEY_WARNING_DAYS` | Días de warning. |
| `API_KEY_MAX_PER_CLIENT` | Max keys por cliente. |
| `APP_CONTEXT_TENANT_BINDING` | Enforce tenant binding. |
| `APP_CONTEXT_IP_ALLOWLIST` | Enforce IP allowlist. |
| `APP_CONTEXT_ANOMALY_DETECTION` | Toggle de anomalías. |
| `APP_CONTEXT_AUDIT` | Habilitar audit. |
| `APP_CONTEXT_LOG_CHANNEL` | Canal de logs. |
| `APP_CONTEXT_LOG_BODY` | Log de body request. |
| `APP_CONTEXT_LOG_RESPONSE` | Log de body response. |
| `APP_CONTEXT_LOG_ALL` | Log de todas las requests. |
| `APP_CONTEXT_LOG_RESPONSES` | Log de responses. |
| `APP_CONTEXT_LOG_FAILED_AUTH` | Log de auth fallida. |

## Evidence
- File: config/app-context.php
  - Symbol: env(...) usages
  - Notes: todas las variables de entorno consumidas.
