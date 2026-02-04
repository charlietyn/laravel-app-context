# Configuration

El archivo `config/app-context.php` controla toda la operación del paquete: canales, autenticación, rate limiting, seguridad, logging y repositorios de clientes.

## 1) Configuración base
| Key | Descripción | Default/Example |
| --- | --- | --- |
| `deny_by_default` | Bloquea requests sin canal reconocido | `true` |
| `default_channel` | Canal default si `deny_by_default=false` | `default` |
| `domain` | Dominio base para extraer subdominio | `APP_CONTEXT_DOMAIN` |
| `detection_strategy` | `auto`, `path`, `subdomain`, `strict` | `auto` |
| `auto_detection_rules` | Reglas host → estrategia | ver archivo |
| `app_context_dev` | entornos dev para `auto` | `local` |

## 2) Canales
Cada entrada en `channels` define detección, auth y permisos:

```php
'channels' => [
    'admin' => [
        'subdomains' => ['admin', 'dashboard'],
        'path_prefixes' => ['/api'],
        'auth_mode' => 'jwt',
        'jwt_audience' => 'admin',
        'allowed_scopes' => ['admin:*'],
        'rate_limit_profile' => 'admin',
        'tenant_mode' => 'multi',
        'features' => ['mfa_required' => false],
        'audit' => ['enabled' => true],
    ],
],
```

## 3) Client repository
| Key | Descripción |
| --- | --- |
| `client_repository.driver` | `config`, `eloquent` o clase custom |
| `client_repository.config` | Clientes definidos en config |
| `client_repository.eloquent` | Tablas/modelos para DB |

El repo se resuelve en tiempo de ejecución y debe implementar `ClientRepositoryInterface`.

## 4) JWT
| Key | Descripción |
| --- | --- |
| `jwt.algorithm` | `HS256`/`RS256` (RS recomendado en prod) |
| `jwt.public_key_path`, `jwt.private_key_path` | rutas RSA |
| `jwt.issuer`, `jwt.verify_iss` | validación de issuer |
| `jwt.verify_aud` | valida `aud` |
| `jwt.allowed_algorithms` | whitelist de algoritmos |
| `jwt.token_sources` | `header`, `query`, `cookie` |
| `jwt.dev_fallback` | fallback HS256 para dev |

## 5) API Key
| Key | Descripción |
| --- | --- |
| `api_key.hash_algorithm` | `argon2id` recomendado |
| `api_key.headers.client_id` | default `X-Client-Id` |
| `api_key.headers.api_key` | default `X-Api-Key` |
| `api_key.rotation_days` | política de rotación |

## 6) Rate limiting
Se define por perfil (`rate_limits.<profile>`), con:
- `global`, `authenticated_global`
- `by` (`user`, `client_id`, `ip`, `user_device`, `ip_or_user`)
- `burst`
- `endpoints` con patrón `METHOD:/path`

## 7) Security & audit
- `security.strict_algorithm_check`, `security.enforce_tenant_binding`, `security.enforce_ip_allowlist`
- `audit.enabled`, `audit.log_all_requests`, `audit.sensitive_headers`

## 8) Public routes
`public_routes` permite saltar autenticación en rutas públicas por:
- `names`
- `name_endings`
- `path_endings`

## Evidence
- File: config/app-context.php
  - Symbol: deny_by_default, default_channel, domain, detection_strategy, channels, client_repository, jwt, api_key, rate_limits, security, audit, public_routes
  - Notes: configuración completa y defaults.
- File: src/AppContextServiceProvider.php
  - Symbol: AppContextServiceProvider::registerClientRepository()
  - Notes: selección dinámica del repositorio de clientes.
