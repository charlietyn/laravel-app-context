# 01-env-matrix

| Key | Declared in | Used in | Suggested action | Risk | Notes |
| --- | --- | --- | --- | --- | --- |
| ADMIN_MFA_REQUIRED | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| API_KEY_CLIENT_ID_HEADER | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| API_KEY_HASH_ALGO | .env.example, docs/README.es.md, docs/README.md (+1 more) | config/app-context.php | KEEP | Low | — |
| API_KEY_HEADER | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| API_KEY_MAX_PER_CLIENT | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| API_KEY_ROTATION_DAYS | .env.example, docs/README.es.md, docs/README.md (+1 more) | config/app-context.php | KEEP | Low | — |
| API_KEY_WARNING_DAYS | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_ANOMALY_DETECTION | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_APPS_TABLE | docs/README.es.md, docs/README.md, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_APP_KEYS_TABLE | docs/README.es.md, docs/README.md, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_APP_KEY_MODEL | documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_APP_MODEL | documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_AUDIT | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_CLIENTS_CONNECTION | documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_CLIENTS_TABLE | docs/README.es.md, docs/README.md, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_CLIENT_DRIVER | docs/README.es.md, docs/README.md, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_DEFAULT_CHANNEL | documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_DENY_BY_DEFAULT | .env.example, docs/README.es.md, docs/README.md (+1 more) | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_DETECTION | .env.example, docs/Documentation.es.md, docs/Documentation.md (+3 more) | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_DEV | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_DOMAIN | .env.example, docs/Documentation.es.md, docs/Documentation.md (+4 more) | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_IP_ALLOWLIST | .env.example, docs/README.es.md, docs/README.md (+1 more) | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_LOG_ALL | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_LOG_BODY | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_LOG_CHANNEL | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_LOG_FAILED_AUTH | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_LOG_RESPONSE | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_LOG_RESPONSES | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_CONTEXT_TENANT_BINDING | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_DEV | .env.example | — | INVESTIGATE | Med | No env() usage found; may be legacy |
| APP_DOMAIN | docs/Documentation.es.md, docs/Documentation.md, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| APP_ENV | docs/Documentation.es.md, docs/Documentation.md | — | INVESTIGATE | Med | Laravel core env; not referenced by package config |
| APP_KEY | docs/README.es.md, docs/README.md, docs/SECURITY.md | config/app-context.php | KEEP | Low | — |
| APP_URL | — | config/app-context.php | DOCUMENT | Med | Used as fallback for JWT issuer |
| JWT_ALGO | .env.example, docs/MIGRATION.md, docs/README.es.md (+2 more) | config/app-context.php | KEEP | Low | — |
| JWT_BLACKLIST_ENABLED | .env.example, docs/README.es.md, docs/README.md (+1 more) | config/app-context.php | KEEP | Low | — |
| JWT_DEV_ALGO | documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| JWT_DEV_FALLBACK | docs/README.es.md, docs/README.md, docs/SECURITY.md (+1 more) | config/app-context.php | KEEP | Low | — |
| JWT_DEV_SECRET | docs/README.es.md, docs/README.md, docs/SECURITY.md (+1 more) | config/app-context.php | KEEP | Low | — |
| JWT_IGNORE_ISSUER_SCHEME | docs/Documentation.es.md, docs/Documentation.md, documentation/ronu/laravel-app-context/docs/04-features/jwt-authentication.md (+2 more) | config/app-context.php | KEEP | Low | — |
| JWT_ISSUER | .env.example, docs/Documentation.es.md, docs/Documentation.md (+4 more) | config/app-context.php | KEEP | Low | — |
| JWT_PRIVATE_KEY_PATH | .env.example, docs/MIGRATION.md, docs/README.es.md (+3 more) | config/app-context.php | KEEP | Low | — |
| JWT_PUBLIC_KEY_PATH | .env.example, docs/MIGRATION.md, docs/README.es.md (+3 more) | config/app-context.php | KEEP | Low | — |
| JWT_REFRESH_TTL | .env.example, docs/README.es.md, docs/README.md (+1 more) | config/app-context.php | KEEP | Low | Ensure units are seconds in app-context config |
| JWT_SECRET | .env.example, docs/MIGRATION.md | — | INVESTIGATE | Med | Used by jwt-auth config, not referenced in this package |
| JWT_TOKEN_SOURCES | documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| JWT_TTL | .env.example, docs/MIGRATION.md, docs/README.es.md (+2 more) | config/app-context.php | KEEP | Low | Ensure units are seconds in app-context config |
| JWT_VERIFY_AUD | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| JWT_VERIFY_ISS | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| RATE_LIMIT_ADMIN_GLOBAL | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| RATE_LIMIT_MOBILE_GLOBAL | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| RATE_LIMIT_PARTNER_GLOBAL | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| RATE_LIMIT_SITE_ANON | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
| RATE_LIMIT_SITE_AUTH | .env.example, documentation/ronu/laravel-app-context/docs/09-reference/env-vars.md | config/app-context.php | KEEP | Low | — |
