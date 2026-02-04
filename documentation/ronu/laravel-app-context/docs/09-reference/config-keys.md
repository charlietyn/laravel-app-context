# Config Keys Reference

Archivo: `config/app-context.php`.

## Core
| Key | Tipo | Descripción |
| --- | --- | --- |
| `deny_by_default` | bool | Bloquea requests sin canal reconocido. |
| `default_channel` | string | Canal default si `deny_by_default=false`. |
| `domain` | string | Dominio base para extraer subdominio. |
| `detection_strategy` | string | `auto`, `path`, `subdomain`, `strict`. |
| `auto_detection_rules` | array | Reglas host → estrategia. |
| `app_context_dev` | array | Envs dev para resolver por path. |

## Client repository
| Key | Tipo | Descripción |
| --- | --- | --- |
| `client_repository.driver` | string | `config`, `eloquent` o clase custom. |
| `client_repository.config` | array | Clientes en config. |
| `client_repository.eloquent` | array | Tablas/modelos para DB. |

## Channels
| Key | Tipo | Descripción |
| --- | --- | --- |
| `channels.*.subdomains` | array | Subdominios válidos. |
| `channels.*.path_prefixes` | array | Prefijos de path. |
| `channels.*.auth_mode` | string | `jwt`, `api_key`, `anonymous`, `jwt_or_anonymous`. |
| `channels.*.jwt_audience` | string | Audiencia esperada. |
| `channels.*.allowed_scopes` | array | Scopes permitidos. |
| `channels.*.allowed_capabilities` | array | Capabilities permitidas. |
| `channels.*.public_scopes` | array | Scopes públicos. |
| `channels.*.anonymous_on_invalid_token` | bool | Fallback para token inválido. |
| `channels.*.rate_limit_profile` | string | Perfil de rate limit. |
| `channels.*.tenant_mode` | string | `single`/`multi`. |
| `channels.*.features` | array | Flags por canal. |
| `channels.*.audit` | array | Overrides de audit. |

## JWT
| Key | Tipo | Descripción |
| --- | --- | --- |
| `jwt.algorithm` | string | `HS256`/`RS256`. |
| `jwt.public_key_path` | string | Ruta de clave pública. |
| `jwt.private_key_path` | string | Ruta de clave privada. |
| `jwt.issuer` | string | Issuer esperado. |
| `jwt.ttl` | int | TTL en segundos. |
| `jwt.refresh_ttl` | int | TTL de refresh. |
| `jwt.blacklist_enabled` | bool | Blacklist activa. |
| `jwt.verify_iss` | bool | Validar issuer. |
| `jwt.ignore_issuer_scheme` | bool | Ignorar esquema http/https. |
| `jwt.verify_aud` | bool | Validar audiencia. |
| `jwt.allowed_algorithms` | array | Algoritmos permitidos. |
| `jwt.token_sources` | array | `header`, `query`, `cookie`. |
| `jwt.dev_fallback` | array | Fallback para dev. |

## API Key
| Key | Tipo | Descripción |
| --- | --- | --- |
| `api_key.hash_algorithm` | string | Algoritmo de hash. |
| `api_key.headers.client_id` | string | Header client ID. |
| `api_key.headers.api_key` | string | Header API key. |
| `api_key.rotation_days` | int | Rotación de keys. |
| `api_key.expiration_warning_days` | int | Días de warning. |
| `api_key.max_keys_per_client` | int | Máximo keys por cliente. |

## Rate limits
| Key | Tipo | Descripción |
| --- | --- | --- |
| `rate_limits.*.global` | string | Límite global. |
| `rate_limits.*.authenticated_global` | string | Límite para autenticados. |
| `rate_limits.*.by` | string | Estrategia de key. |
| `rate_limits.*.burst` | string | Límite burst. |
| `rate_limits.*.endpoints` | array | Límite por endpoint. |

## Security
| Key | Tipo | Descripción |
| --- | --- | --- |
| `security.strict_algorithm_check` | bool | Whitelist estricta de algoritmos. |
| `security.enforce_tenant_binding` | bool | Enforce tenant binding. |
| `security.enforce_ip_allowlist` | bool | Enforce allowlist. |
| `security.anomaly_detection` | array | Flags de anomalías. |

## Audit
| Key | Tipo | Descripción |
| --- | --- | --- |
| `audit.enabled` | bool | Activar auditoría. |
| `audit.log_channel` | string | Canal de log. |
| `audit.include_request_body` | bool | Log de body request. |
| `audit.include_response_body` | bool | Log de body response. |
| `audit.log_all_requests` | bool | Log de todas las requests. |
| `audit.log_responses` | bool | Log de responses. |
| `audit.log_failed_auth` | bool | Log de auth fallida. |
| `audit.sensitive_headers` | array | Headers a redactar. |

## Public routes
| Key | Tipo | Descripción |
| --- | --- | --- |
| `public_routes.names` | array | Rutas públicas por nombre. |
| `public_routes.name_endings` | array | Rutas públicas por sufijo de nombre. |
| `public_routes.path_endings` | array | Rutas públicas por sufijo de path. |

## Evidence
- File: config/app-context.php
  - Symbol: (archivo completo)
  - Notes: source oficial de todas las keys.
