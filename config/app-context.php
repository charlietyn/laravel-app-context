<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Client Repository Configuration
    |--------------------------------------------------------------------------
    |
    | Configure how API clients are stored and retrieved. The library supports
    | multiple backends without requiring database migrations.
    |
    | Available drivers:
    | - 'config': Define clients directly in configuration (no database)
    | - 'eloquent': Store clients in database (requires migration)
    | - Custom class: Any class implementing ClientRepositoryInterface
    |
    */
    'client_repository' => [
        // Driver: 'config', 'eloquent', or fully qualified class name
        'driver' => env('APP_CONTEXT_CLIENT_DRIVER', 'config'),

        // Configuration for 'config' driver (no database required)
        'config' => [
            'hash_algorithm' => env('API_KEY_HASH_ALGO', 'bcrypt'),
            'prefix_length' => 10,
            'key_length' => 32,

            // Define clients here for simple setups
            // Generate hash: php artisan tinker --execute="echo Hash::make('your-secret-key');"
            'clients' => [
                // Example client (commented out):
                // 'my-partner' => [
                //     'name' => 'My Partner App',
                //     'key_hash' => '$2y$10$...', // bcrypt/argon2id hash of the API key
                //     'channel' => 'partner',
                //     'tenant_id' => null,
                //     'capabilities' => ['partner:*'],
                //     'ip_allowlist' => [], // ['192.168.1.0/24', '10.0.0.1']
                //     'is_active' => true,
                //     'is_revoked' => false,
                //     'expires_at' => null, // '2025-12-31 23:59:59'
                //     'metadata' => [
                //         'rate_limit_tier' => 'default',
                //         'webhook_url' => null,
                //     ],
                // ],
            ],
        ],

        // Configuration for 'eloquent' driver (database required)
        'eloquent' => [
            // Legacy single-table schema
            'table' => env('APP_CONTEXT_CLIENTS_TABLE', 'api_clients'),
            // Multi-table schema (recommended)
            'apps_table' => env('APP_CONTEXT_APPS_TABLE', 'api_apps'),
            'app_keys_table' => env('APP_CONTEXT_APP_KEYS_TABLE', 'api_app_keys'),
            // Optional: pass your Eloquent model classes (preferred for multi-table)
            'app_model' => env('APP_CONTEXT_APP_MODEL'),
            'app_key_model' => env('APP_CONTEXT_APP_KEY_MODEL'),
            'connection' => env('APP_CONTEXT_CLIENTS_CONNECTION', null),
            'hash_algorithm' => env('API_KEY_HASH_ALGO', 'argon2id'),
            'prefix_length' => 10,
            'key_length' => 32,
            'async_tracking' => true, // Track usage asynchronously
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Default Behavior
    |--------------------------------------------------------------------------
    |
    | deny_by_default: When true, requests that don't match any channel
    | configuration will be rejected with 403. When false, they'll be
    | treated as anonymous requests to a default channel.
    |
    | Recommended: true for production, false for initial development
    |
    */
    'deny_by_default' => env('APP_CONTEXT_DENY_BY_DEFAULT', true),

    /*
    |--------------------------------------------------------------------------
    | Default Channel (when deny_by_default = false)
    |--------------------------------------------------------------------------
    |
    | If no channel matches and deny_by_default is disabled, the resolver will
    | create an anonymous context for this channel ID.
    |
    */
    'default_channel' => env('APP_CONTEXT_DEFAULT_CHANNEL', 'default'),

    /*
    |--------------------------------------------------------------------------
    | Application Domain
    |--------------------------------------------------------------------------
    |
    | Base domain used for subdomain extraction. For example, if your domain
    | is "myapp.com", then "admin.myapp.com" will resolve subdomain as "admin".
    |
    */
    'domain' => env('APP_CONTEXT_DOMAIN', env('APP_DOMAIN', 'localhost')),

    /*
    |--------------------------------------------------------------------------
    | Detection Strategy
    |--------------------------------------------------------------------------
    |
    | Defines how channels are detected from incoming requests.
    |
    | Available strategies:
    | - 'auto': Auto-detect based on host (localhost=path, domains=subdomain)
    | - 'path': Path-based only (for development: /api/*, /mobile/*)
    | - 'subdomain': Subdomain-based only (admin.app.com, mobile.app.com)
    | - 'strict': Both subdomain AND path must match same channel (max security)
    |
    | Recommended:
    | - Development: 'auto' or 'path'
    | - Production: 'auto' or 'subdomain'
    | - High Security: 'strict'
    |
    */
    'detection_strategy' => env('APP_CONTEXT_DETECTION', 'auto'),

    /*
    |--------------------------------------------------------------------------
    | Auto-Detection Rules
    |--------------------------------------------------------------------------
    |
    | When strategy is 'auto', these rules determine which detection method
    | to use based on the request host. Patterns support wildcards (*).
    |
    | Format: 'host_pattern' => 'strategy'
    | Evaluation order: top to bottom (first match wins)
    |
    */
    'auto_detection_rules' => [
        'localhost' => 'path',              // http://localhost/api/login
        '127.0.0.1' => 'path',              // http://127.0.0.1/mobile/orders
        '*.localhost' => 'subdomain',       // http://api.localhost/users (Docker)
        '*.ngrok.io' => 'path',             // https://abc.ngrok.io/mobile/login
        '*.ngrok-free.app' => 'path',       // https://abc.ngrok-free.app/api/users
        '*.test' => 'path',                 // http://myapp.test/mobile/orders (Valet)
        '*.local' => 'path',                // http://myapp.local/api/login
        // All other hosts default to 'subdomain' (production)
    ],

    /*
    |--------------------------------------------------------------------------
    | Development Contexts
    |--------------------------------------------------------------------------
    |
    | Environment labels that should prefer path detection when no subdomain
    | is present in auto mode. Useful for staging/dev environments.
    |
    | Set via APP_CONTEXT_DEV env var (comma-separated).
    | Example: APP_CONTEXT_DEV=local,staging
    |
    */
    'app_context_dev' => array_filter(
        array_map('trim', explode(',', env('APP_CONTEXT_DEV', 'local'))),
        static fn(string $value): bool => $value !== ''
    ),

    /*
    |--------------------------------------------------------------------------
    | Channel Definitions
    |--------------------------------------------------------------------------
    |
    | Define your application channels here. Each channel specifies:
    | - subdomains: Array of subdomains that resolve to this channel
    | - path_prefixes: Array of URL prefixes that resolve to this channel
    | - auth_mode: Authentication method (jwt, api_key, anonymous, jwt_or_anonymous)
    | - jwt_audience: Expected JWT audience claim for this channel
    | - allowed_scopes: Scopes available in this channel (for JWT)
    | - allowed_capabilities: Capabilities available (for API Key)
    | - public_scopes: Public scopes for jwt_or_anonymous/anonymous access
    | - anonymous_on_invalid_token: Allow fallback to anonymous for invalid JWTs
    | - rate_limit_profile: Which rate limit profile to use
    | - tenant_mode: single or multi-tenant
    | - features: Channel-specific feature flags
    | - audit: Channel-specific audit overrides
    |
    */
    'channels' => [

        /*
        |----------------------------------------------------------------------
        | Mobile Channel
        |----------------------------------------------------------------------
        | For native mobile applications (iOS/Android)
        */
        'mobile' => [
            'subdomains' => ['mobile', 'm'],
            'path_prefixes' => ['/mobile'],
            'auth_mode' => 'jwt',
            'jwt_audience' => 'mobile',
            'allowed_scopes' => [
                'mobile:*',
                'user:profile:*',
                'cart:*',
                'checkout:*',
            ],
            'rate_limit_profile' => 'mobile',
            'tenant_mode' => 'multi',
            'features' => [
                'device_fingerprinting' => true,
                'refresh_token_rotation' => true,
                'allow_anonymous' => false,
            ],
        ],

        /*
        |----------------------------------------------------------------------
        | Admin Channel
        |----------------------------------------------------------------------
        | For administrative dashboard
        */
        'admin' => [
            'subdomains' => ['admin', 'dashboard'],
            'path_prefixes' => ['/api'],
            'auth_mode' => 'jwt',
            'jwt_audience' => 'admin',
            'allowed_scopes' => [
                'admin:*',
                'reports:*',
                'analytics:*',
                'settings:*',
            ],
            'rate_limit_profile' => 'admin',
            'tenant_mode' => 'multi',
            'features' => [
                'mfa_required' => env('ADMIN_MFA_REQUIRED', false),
                'session_timeout' => 1800, // 30 min
                'audit_all_requests' => true,
                'allow_anonymous' => false,
            ],
            'audit' => [
                'enabled' => true,
                'log_all_requests' => false,
            ],
        ],

        /*
        |----------------------------------------------------------------------
        | Site Channel
        |----------------------------------------------------------------------
        | For public website / storefront
        */
        'site' => [
            'subdomains' => ['www', null], // null = root domain
            'path_prefixes' => ['/site', '/shop'],
            'auth_mode' => 'jwt_or_anonymous',
            'jwt_audience' => 'site',
            'allowed_scopes' => [
                'site:*',
                'cart:*',
                'checkout:*',
                'catalog:browse',
            ],
            'public_scopes' => [
                'catalog:browse',
                'public:read',
            ],
            'anonymous_on_invalid_token' => false,
            'rate_limit_profile' => 'site',
            'tenant_mode' => 'single',
            'features' => [
                'allow_anonymous' => true,
                'captcha_on_checkout' => true,
            ],
            'audit' => [
                'enabled' => false,
                'log_all_requests' => false,
            ],
        ],

        /*
        |----------------------------------------------------------------------
        | Partner Channel (B2B)
        |----------------------------------------------------------------------
        | For external partner integrations via API Key
        */
        'partner' => [
            'subdomains' => ['api-partners', 'partners', 'b2b'],
            'path_prefixes' => ['/partner', '/b2b'],
            'auth_mode' => 'api_key',
            'allowed_capabilities' => [
                'partner:*',
                'webhooks:*',
                'inventory:*',
            ],
            'rate_limit_profile' => 'partner',
            'tenant_mode' => 'multi',
            'features' => [
                'ip_allowlist_required' => false,
                'hmac_signature' => false,
                'mtls' => false,
                'track_usage' => true,
            ],
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limit Profiles
    |--------------------------------------------------------------------------
    |
    | Define rate limits per channel. Each profile can specify:
    | - global: Default limit for all endpoints
    | - authenticated_global: Limit for authenticated requests
    | - by: What to rate limit by (user, ip, client_id, user_device)
    | - burst: Short-term burst limit
    | - endpoints: Specific endpoint limits (pattern => limit)
    |
    | Limit syntax: {requests}/{period}
    | Periods: s=second, m=minute, h=hour, d=day
    |
    */
    'rate_limits' => [
        'mobile' => [
            'global' => env('RATE_LIMIT_MOBILE_GLOBAL', '60/m'),
            'by' => 'user_device',
            'burst' => '10/s',
            'endpoints' => [
                'POST:/mobile/orders' => '10/m',
                'POST:/mobile/checkout' => '5/m',
            ],
        ],

        'admin' => [
            'global' => env('RATE_LIMIT_ADMIN_GLOBAL', '120/m'),
            'by' => 'user',
            'burst' => '20/s',
            'endpoints' => [
                'GET:/api/reports/export' => '5/m',
                'GET:/api/*/export-excel' => '10/m',
                'GET:/api/*/export-pdf' => '10/m',
                'DELETE:/api/*/delete-all' => '2/m',
                'POST:/api/*/update-multiple' => '20/m',
            ],
        ],

        'site' => [
            'global' => env('RATE_LIMIT_SITE_ANON', '30/m'),
            'authenticated_global' => env('RATE_LIMIT_SITE_AUTH', '60/m'),
            'by' => 'ip_or_user',
            'burst' => '5/s',
            'endpoints' => [
                'POST:/site/checkout' => '3/m',
                'POST:/site/orders' => '5/m',
            ],
        ],

        'partner' => [
            'global' => env('RATE_LIMIT_PARTNER_GLOBAL', '600/m'),
            'by' => 'client_id',
            'burst' => '50/s',
            'endpoints' => [
                'POST:/partner/orders' => '100/m',
                'GET:/partner/inventory' => '300/m',
                'POST:/partner/webhooks' => '50/m',
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | JWT Configuration
    |--------------------------------------------------------------------------
    |
    | JWT-specific settings. These complement/override config/jwt.php from
    | php-open-source-saver/jwt-auth.
    |
    */
    'jwt' => [
        // Algorithm to use (RS256 recommended for production)
        'algorithm' => env('JWT_ALGO', 'HS256'),

        // Key paths for RS256
        'public_key_path' => env('JWT_PUBLIC_KEY_PATH', storage_path('keys/jwt-public.pem')),
        'private_key_path' => env('JWT_PRIVATE_KEY_PATH', storage_path('keys/jwt-private.pem')),

        // Expected issuer (usually your app URL)
        'issuer' => env('JWT_ISSUER', env('APP_URL', 'http://localhost')),

        // Token TTL in seconds
        'ttl' => env('JWT_TTL', 3600), // 1 hour

        // Refresh token TTL in seconds
        'refresh_ttl' => env('JWT_REFRESH_TTL', 1209600), // 14 days

        // Enable token blacklist (requires cache/Redis)
        'blacklist_enabled' => env('JWT_BLACKLIST_ENABLED', true),

        // Grace period for blacklist (handles race conditions)
        'blacklist_grace_period' => 30,

        // Verify issuer claim
        'verify_iss' => env('JWT_VERIFY_ISS', true),

        // Verify audience claim
        'verify_aud' => env('JWT_VERIFY_AUD', true),

        // Whitelist of allowed algorithms (prevents algorithm confusion attacks)
        // CRITICAL: Never include 'none' in this list
        'allowed_algorithms' => ['HS256', 'RS256', 'RS384', 'RS512'],

        // Token sources to accept (header, query, cookie)
        'token_sources' => array_filter(
            array_map('trim', explode(',', env('JWT_TOKEN_SOURCES', 'header,query,cookie'))),
            static fn(string $value): bool => $value !== ''
        ),

        // Development fallback when RSA keys are missing
        'dev_fallback' => [
            // Enable fallback to symmetric signing in dev-like environments
            'enabled' => env('JWT_DEV_FALLBACK', true),
            // Algorithm used when falling back
            'algorithm' => env('JWT_DEV_ALGO', 'HS256'),
            // Secret used for dev fallback (defaults to APP_KEY)
            'secret' => env('JWT_DEV_SECRET', env('APP_KEY')),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | API Key Configuration
    |--------------------------------------------------------------------------
    |
    | Settings for API Key authentication (B2B/partner channel).
    |
    */
    'api_key' => [
        // Hash algorithm for API keys (argon2id recommended)
        'hash_algorithm' => env('API_KEY_HASH_ALGO', 'argon2id'),

        // Headers used to receive credentials
        'headers' => [
            'client_id' => env('API_KEY_CLIENT_ID_HEADER', 'X-Client-Id'),
            'api_key' => env('API_KEY_HEADER', 'X-Api-Key'),
        ],

        // Key rotation settings
        'rotation_days' => env('API_KEY_ROTATION_DAYS', 90),
        'expiration_warning_days' => env('API_KEY_WARNING_DAYS', 15),

        // Maximum keys per client
        'max_keys_per_client' => env('API_KEY_MAX_PER_CLIENT', 5),

        // Key format
        'prefix_length' => 10,
        'key_length' => 32,
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Features
    |--------------------------------------------------------------------------
    |
    | Additional security settings.
    |
    */
    'security' => [
        // Strict algorithm checking (recommended: true)
        'strict_algorithm_check' => true,

        // Enforce tenant binding (prevent tenant hopping)
        'enforce_tenant_binding' => env('APP_CONTEXT_TENANT_BINDING', true),

        // Require IP allowlist for API key authentication
        'enforce_ip_allowlist' => env('APP_CONTEXT_IP_ALLOWLIST', false),

        // Anomaly detection settings
        'anomaly_detection' => [
            'enabled' => env('APP_CONTEXT_ANOMALY_DETECTION', false),
            'max_ip_changes_per_hour' => 3,
            'max_device_changes_per_day' => 5,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Audit & Logging
    |--------------------------------------------------------------------------
    |
    | Configure audit logging for security and debugging.
    |
    */
    'audit' => [
        // Enable audit logging
        'enabled' => env('APP_CONTEXT_AUDIT', true),

        // Log channel to use
        'log_channel' => env('APP_CONTEXT_LOG_CHANNEL', 'stack'),

        // Include request body in logs (careful with sensitive data)
        'include_request_body' => env('APP_CONTEXT_LOG_BODY', false),

        // Include response body in logs
        'include_response_body' => env('APP_CONTEXT_LOG_RESPONSE', false),

        // Log all requests (not just errors)
        'log_all_requests' => env('APP_CONTEXT_LOG_ALL', false),

        // Log all responses
        'log_responses' => env('APP_CONTEXT_LOG_RESPONSES', false),

        // Log failed authentication attempts
        'log_failed_auth' => env('APP_CONTEXT_LOG_FAILED_AUTH', true),

        // Headers to redact from logs
        'sensitive_headers' => [
            'authorization',
            'x-api-key',
            'cookie',
            'x-csrf-token',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Public Routes
    |--------------------------------------------------------------------------
    |
    | Routes that don't require authentication. These are checked by name
    | and by path ending.
    |
    */
    'public_routes' => [
        // By route name
        'names' => [
            'login',
            'register',
            'auth.login',
            'auth.register',
            'password.reset',
            'password.forgot',
        ],

        // By name ending
        'name_endings' => [
            '.login',
            '.register',
            '.password.reset',
            '.password.forgot',
        ],

        // By path ending
        'path_endings' => [
            '/login',
            '/register',
            '/password/reset',
            '/password/forgot',
        ],
    ],
];
