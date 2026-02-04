# Environment variables

This package uses environment variables via `config/app-context.php`. Configure them in your `.env` file as needed.

| Variable | Purpose | Default |
| --- | --- | --- |
| `APP_CONTEXT_CLIENT_DRIVER` | Client repository driver (`config`, `eloquent`, or class name). | `config` |
| `API_KEY_HASH_ALGO` | Hash algorithm for API keys. | `argon2id` (eloquent) / `bcrypt` (config) |
| `APP_CONTEXT_CLIENTS_TABLE` | Legacy single-table client table name. | `api_clients` |
| `APP_CONTEXT_APPS_TABLE` | Multi-table apps table name. | `api_apps` |
| `APP_CONTEXT_APP_KEYS_TABLE` | Multi-table app keys table name. | `api_app_keys` |
| `APP_CONTEXT_APP_MODEL` | Custom Eloquent model for apps. | `null` |
| `APP_CONTEXT_APP_KEY_MODEL` | Custom Eloquent model for app keys. | `null` |
| `APP_CONTEXT_CLIENTS_CONNECTION` | Database connection for clients. | `null` |
| `APP_CONTEXT_DENY_BY_DEFAULT` | Reject requests when no channel matches. | `true` |
| `APP_CONTEXT_DEFAULT_CHANNEL` | Default channel when deny-by-default is false. | `default` |
| `APP_CONTEXT_DOMAIN` | Domain for subdomain extraction. | `APP_DOMAIN` or `localhost` |
| `APP_DOMAIN` | Optional fallback for `APP_CONTEXT_DOMAIN`. | `localhost` |
| `APP_CONTEXT_DETECTION` | Detection strategy (`auto`, `path`, `subdomain`, `strict`). | `auto` |
| `APP_CONTEXT_DEV` | Comma-separated dev envs for auto detection. | `local` |
| `ADMIN_MFA_REQUIRED` | Example admin feature flag. | `false` |
| `RATE_LIMIT_MOBILE_GLOBAL` | Mobile global rate limit. | `60/m` |
| `RATE_LIMIT_ADMIN_GLOBAL` | Admin global rate limit. | `120/m` |
| `RATE_LIMIT_SITE_ANON` | Site anonymous rate limit. | `30/m` |
| `RATE_LIMIT_SITE_AUTH` | Site authenticated rate limit. | `60/m` |
| `RATE_LIMIT_PARTNER_GLOBAL` | Partner global rate limit. | `600/m` |
| `JWT_ALGO` | JWT algorithm. | `HS256` |
| `JWT_PUBLIC_KEY_PATH` | JWT public key path (RS256). | `storage_path('keys/jwt-public.pem')` |
| `JWT_PRIVATE_KEY_PATH` | JWT private key path (RS256). | `storage_path('keys/jwt-private.pem')` |
| `JWT_ISSUER` | Expected JWT issuer. | `APP_URL` or `http://localhost` |
| `APP_URL` | Fallback for JWT issuer. | `http://localhost` |
| `JWT_TTL` | JWT TTL in seconds. | `3600` |
| `JWT_REFRESH_TTL` | JWT refresh TTL in seconds. | `1209600` |
| `JWT_BLACKLIST_ENABLED` | Enable JWT blacklist checks. | `true` |
| `JWT_VERIFY_ISS` | Verify issuer claim. | `true` |
| `JWT_IGNORE_ISSUER_SCHEME` | Ignore scheme when verifying issuer. | `false` |
| `JWT_VERIFY_AUD` | Verify audience claim. | `true` |
| `JWT_TOKEN_SOURCES` | Token sources (comma-separated). | `header,query,cookie` |
| `JWT_DEV_FALLBACK` | Enable dev RSA fallback. | `true` |
| `JWT_DEV_ALGO` | Dev fallback algorithm. | `HS256` |
| `JWT_DEV_SECRET` | Dev fallback secret. | `APP_KEY` |
| `APP_KEY` | Fallback secret for dev fallback. | (Laravel default) |
| `API_KEY_CLIENT_ID_HEADER` | Header for client ID. | `X-Client-Id` |
| `API_KEY_HEADER` | Header for API key. | `X-Api-Key` |
| `API_KEY_ROTATION_DAYS` | Suggested rotation window. | `90` |
| `API_KEY_WARNING_DAYS` | Expiration warning window. | `15` |
| `API_KEY_MAX_PER_CLIENT` | Maximum keys per client. | `5` |
| `APP_CONTEXT_TENANT_BINDING` | Enforce tenant binding. | `true` |
| `APP_CONTEXT_IP_ALLOWLIST` | Enforce IP allowlist. | `false` |
| `APP_CONTEXT_ANOMALY_DETECTION` | Enable anomaly detection. | `false` |
| `APP_CONTEXT_AUDIT` | Enable audit logging. | `true` |
| `APP_CONTEXT_LOG_CHANNEL` | Log channel for audit logs. | `stack` |
| `APP_CONTEXT_LOG_BODY` | Include request body in logs. | `false` |
| `APP_CONTEXT_LOG_RESPONSE` | Include response body in logs. | `false` |
| `APP_CONTEXT_LOG_ALL` | Log all requests. | `false` |
| `APP_CONTEXT_LOG_RESPONSES` | Log all responses. | `false` |
| `APP_CONTEXT_LOG_FAILED_AUTH` | Log failed auth attempts. | `true` |

[Back to index](../index.md)
