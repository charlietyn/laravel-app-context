# Configuration reference

This page summarizes the main configuration keys in `config/app-context.php`. For the exhaustive list and defaults, review the config file directly.

## Top-level keys

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `client_repository` | array | `[]` | Configure API client storage (config, eloquent, or custom). |
| `deny_by_default` | bool | `true` | If true, requests that match no channel are rejected. |
| `default_channel` | string | `default` | Channel used when `deny_by_default` is false and no channel matches. |
| `domain` | string | `localhost` | Base domain for subdomain extraction. |
| `detection_strategy` | string | `auto` | `auto`, `path`, `subdomain`, or `strict`. |
| `auto_detection_rules` | array | `[]` | Host-to-strategy rules for auto detection. |
| `app_context_dev` | array | `['local']` | Environments treated as development for auto detection. |
| `channels` | array | `[]` | Channel definitions. |
| `rate_limits` | array | `[]` | Rate limit profiles keyed by name. |
| `jwt` | array | `[]` | JWT verification and behavior configuration. |
| `api_key` | array | `[]` | API key verification configuration. |
| `security` | array | `[]` | Security enforcement options. |
| `audit` | array | `[]` | Audit logging configuration. |
| `public_routes` | array | `[]` | Public route detection (for optional auth). |

## Client repository (`client_repository`)

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `driver` | string | `config` | `config`, `eloquent`, or custom class implementing `ClientRepositoryInterface`. |
| `config` | array | `[]` | Config-based repository options (clients, hash algorithm, key length). |
| `eloquent` | array | `[]` | Eloquent repository options (table names, models, connection, async tracking). |

## Channel definition (`channels.{channel}`)

| Key | Type | Description |
| --- | --- | --- |
| `subdomains` | array | Subdomains that map to the channel. Use `null` to represent the root domain. |
| `path_prefixes` | array | URL prefixes that map to the channel. |
| `auth_mode` | string | `jwt`, `api_key`, `anonymous`, or `jwt_or_anonymous`. |
| `jwt_audience` | string | Expected JWT `aud` for this channel. |
| `allowed_scopes` | array | Allowed JWT scopes for channel. |
| `allowed_capabilities` | array | Allowed API key capabilities for channel. |
| `public_scopes` | array | Public scopes for anonymous/optional access. |
| `anonymous_on_invalid_token` | bool | Allow `jwt_or_anonymous` fallback on invalid JWT. |
| `rate_limit_profile` | string | Rate limit profile name. |
| `tenant_mode` | string | `single` or `multi`. |
| `features` | array | Channel feature flags (e.g., `allow_anonymous`). |
| `audit` | array | Channel-specific audit overrides. |

## Rate limits (`rate_limits.{profile}`)

| Key | Type | Description |
| --- | --- | --- |
| `global` | string | Default limit for anonymous requests. |
| `authenticated_global` | string | Default limit for authenticated requests. |
| `by` | string | Rate limit key strategy (`user`, `client_id`, `ip`, `user_device`, `ip_or_user`). |
| `burst` | string | Optional burst limit. |
| `endpoints` | array | Endpoint-specific limits (pattern => limit). |

## JWT (`jwt`)

| Key | Type | Description |
| --- | --- | --- |
| `algorithm` | string | Algorithm to expect (`HS256`, `RS256`, etc.). |
| `public_key_path` | string | Public key path for RSA algorithms. |
| `private_key_path` | string | Private key path for RSA algorithms. |
| `issuer` | string | Expected issuer claim. |
| `ttl` | int | Token TTL in seconds. |
| `refresh_ttl` | int | Refresh TTL in seconds. |
| `blacklist_enabled` | bool | Whether to enable blacklist checks. |
| `blacklist_grace_period` | int | Grace period for blacklist behavior. |
| `verify_iss` | bool | Enforce issuer validation. |
| `ignore_issuer_scheme` | bool | Ignore scheme when validating issuer. |
| `verify_aud` | bool | Enforce audience validation. |
| `allowed_algorithms` | array | Allowed algorithms (no `none`). |
| `token_sources` | array | Token sources to accept (`header`, `query`, `cookie`). |
| `dev_fallback` | array | Development fallback when RSA keys are missing. |

## API key (`api_key`)

| Key | Type | Description |
| --- | --- | --- |
| `hash_algorithm` | string | Hash algorithm for API keys (e.g., `argon2id`). |
| `headers.client_id` | string | Header name for client ID. |
| `headers.api_key` | string | Header name for API key. |
| `rotation_days` | int | Suggested rotation window. |
| `expiration_warning_days` | int | Warning window before expiration. |
| `max_keys_per_client` | int | Maximum keys per client. |
| `prefix_length` | int | Prefix length for generated keys. |
| `key_length` | int | Secret length for generated keys. |

## Security (`security`)

| Key | Type | Description |
| --- | --- | --- |
| `strict_algorithm_check` | bool | Enforce strict algorithm checks. |
| `enforce_tenant_binding` | bool | Enforce tenant binding in middleware. |
| `enforce_ip_allowlist` | bool | Require IP allowlist for API key auth. |
| `anomaly_detection` | array | Enable anomaly detection settings (currently informational). |

## Audit (`audit`)

| Key | Type | Description |
| --- | --- | --- |
| `enabled` | bool | Enable audit logging middleware. |
| `log_channel` | string | Log channel to use. |
| `include_request_body` | bool | Include JSON body in logs. |
| `include_response_body` | bool | Include response body in logs. |
| `log_all_requests` | bool | Log all requests (not just errors). |
| `log_responses` | bool | Log all responses. |
| `log_failed_auth` | bool | Log failed auth attempts. |
| `sensitive_headers` | array | Headers to redact in logs. |

## Public routes (`public_routes`)

| Key | Type | Description |
| --- | --- | --- |
| `names` | array | Exact route names that are public. |
| `name_endings` | array | Route name suffixes that are public. |
| `path_endings` | array | URL path suffixes that are public. |

[Back to index](../index.md)
