# Migration Guide

This guide covers migrating to Laravel App Context from other authentication systems and upgrading between versions.

## Table of Contents

1. [From Laravel Native Auth](#from-laravel-native-auth)
2. [From Laravel Sanctum](#from-laravel-sanctum)
3. [From Laravel Passport](#from-laravel-passport)
4. [From Custom JWT Implementation](#from-custom-jwt-implementation)
5. [Repository Migration](#repository-migration)
6. [Version Upgrades](#version-upgrades)

---

## From Laravel Native Auth

### Conceptual Differences

| Concept | Laravel Native | Laravel App Context |
|---------|---------------|---------------------|
| Authentication | Single auth guard | Multiple channels with different auth modes |
| Tokens | Session-based | JWT or API Key |
| Authorization | Gates/Policies | Scopes/Capabilities |
| Rate Limiting | `throttle:api` | Context-aware `app.throttle` |
| Middleware | `auth:api` | `app-context` group |

### Migration Steps

#### Step 1: Install the Package

```bash
composer require ronu/laravel-app-context
php artisan vendor:publish --tag=app-context-config
```

#### Step 2: Configure JWT

```bash
# Generate RSA keys
mkdir -p storage/jwt
openssl genrsa -out storage/jwt/private.pem 4096
openssl rsa -in storage/jwt/private.pem -pubout -out storage/jwt/public.pem
```

Update `.env`:

```env
JWT_ALGO=RS256
JWT_PUBLIC_KEY_PATH=storage/jwt/public.pem
JWT_PRIVATE_KEY_PATH=storage/jwt/private.pem
JWT_ISSUER=https://your-app.com
JWT_TTL=3600
```

#### Step 3: Configure Channels

Edit `config/app-context.php`:

```php
'channels' => [
    'api' => [
        'subdomains' => ['api'],
        'path_prefixes' => ['/api'],
        'auth_mode' => 'jwt',
        'jwt_audience' => 'api',
        'allowed_scopes' => ['api:*'],
    ],
],
```

#### Step 4: Update Routes

**Before:**

```php
// routes/api.php
Route::middleware('auth:api')->group(function () {
    Route::get('/user', [UserController::class, 'show']);
});
```

**After:**

```php
// routes/api.php
Route::middleware(['app-context'])->group(function () {
    Route::get('/user', [UserController::class, 'show'])
        ->middleware('app.requires:api:user:read');
});
```

#### Step 5: Update Login Controller

**Before:**

```php
public function login(Request $request)
{
    $credentials = $request->validate([...]);

    if (Auth::attempt($credentials)) {
        $request->session()->regenerate();
        return redirect('/dashboard');
    }

    return back()->withErrors(['email' => 'Invalid credentials']);
}
```

**After:**

```php
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Ronu\AppContext\Context\AppContext;

public function login(Request $request, AppContext $context)
{
    $credentials = $request->validate([...]);

    if (!Auth::attempt($credentials)) {
        return response()->json(['error' => 'Invalid credentials'], 401);
    }

    $claims = [
        'aud' => $context->getAppId(),
        'scp' => $this->getUserScopes(Auth::user()),
    ];

    $token = JWTAuth::claims($claims)->fromUser(Auth::user());

    return response()->json([
        'access_token' => $token,
        'token_type' => 'Bearer',
        'expires_in' => config('app-context.jwt.ttl'),
    ]);
}
```

#### Step 6: Update Authorization Checks

**Before:**

```php
public function update(Request $request, Post $post)
{
    $this->authorize('update', $post);
    // ...
}
```

**After:**

```php
public function update(Request $request, Post $post, AppContext $context)
{
    $context->requires('api:posts:update');
    // Or combine with policies
    $this->authorize('update', $post);
    // ...
}
```

---

## From Laravel Sanctum

### Conceptual Differences

| Concept | Sanctum | Laravel App Context |
|---------|---------|---------------------|
| Token Type | Random strings | JWT (structured) |
| Token Storage | Database | Stateless (verify signature) |
| Abilities | Token abilities | Scopes in JWT claims |
| API Tokens | Personal access tokens | API Keys (for M2M) |

### Migration Steps

#### Step 1: Export Existing Tokens

Before migration, document existing tokens and their abilities:

```php
$tokens = PersonalAccessToken::with('tokenable')->get();
foreach ($tokens as $token) {
    Log::info('Token to migrate', [
        'user_id' => $token->tokenable_id,
        'abilities' => $token->abilities,
        'name' => $token->name,
    ]);
}
```

#### Step 2: Map Abilities to Scopes

Create a mapping from Sanctum abilities to scopes:

```php
$abilityMap = [
    'read' => 'api:read',
    'create' => 'api:create',
    'update' => 'api:update',
    'delete' => 'api:delete',
    '*' => 'api:*',
];
```

#### Step 3: Update Token Issuance

**Before (Sanctum):**

```php
$token = $user->createToken('api-token', ['read', 'create'])->plainTextToken;
```

**After (App Context):**

```php
$claims = [
    'aud' => $context->getAppId(),
    'scp' => ['api:read', 'api:create'],
];

$token = JWTAuth::claims($claims)->fromUser($user);
```

#### Step 4: Update Authorization Checks

**Before (Sanctum):**

```php
if ($request->user()->tokenCan('update')) {
    // ...
}
```

**After (App Context):**

```php
if ($context->hasScope('api:update')) {
    // ...
}
// Or use middleware
Route::middleware(['app.requires:api:update'])->...
```

#### Step 5: Remove Sanctum

```bash
composer remove laravel/sanctum
```

Remove from config/app.php if manually registered.

Delete migration or table if no longer needed:

```bash
php artisan migrate:rollback --path=database/migrations/xxxx_create_personal_access_tokens_table.php
```

---

## From Laravel Passport

### Conceptual Differences

| Concept | Passport | Laravel App Context |
|---------|----------|---------------------|
| OAuth2 | Full implementation | Not OAuth2 (simpler) |
| Token Type | OAuth access tokens | JWT |
| Scopes | OAuth scopes | JWT scopes |
| Clients | OAuth clients | API clients (for M2M) |

### Migration Steps

#### Step 1: Identify OAuth Clients

```php
$clients = \Laravel\Passport\Client::all();
foreach ($clients as $client) {
    Log::info('Client to migrate', [
        'id' => $client->id,
        'name' => $client->name,
        'redirect' => $client->redirect,
    ]);
}
```

#### Step 2: Migrate M2M Clients

For machine-to-machine (client credentials) clients, create API keys:

```php
// Using Eloquent driver
$repository = app(ClientRepositoryInterface::class);
$keyData = $repository->generateKey();

$repository->create([
    'app_code' => 'passport-client-1',
    'name' => $passportClient->name,
    'key_hash' => $keyData['hash'],
    'key_prefix' => $keyData['prefix'],
    'channel' => 'partner',
    'capabilities' => ['partner:*'],
]);

// Provide $keyData['key'] to the client
```

#### Step 3: Update Token Generation

**Before (Passport):**

```php
$token = $user->createToken('Personal Access Token', ['read', 'write'])->accessToken;
```

**After (App Context):**

```php
$claims = [
    'aud' => $context->getAppId(),
    'scp' => ['api:read', 'api:write'],
];

$token = JWTAuth::claims($claims)->fromUser($user);
```

#### Step 4: Update Scope Checks

**Before (Passport):**

```php
Route::middleware(['auth:api', 'scope:read'])->...
```

**After (App Context):**

```php
Route::middleware(['app-context', 'app.requires:api:read'])->...
```

#### Step 5: Remove Passport

```bash
composer remove laravel/passport
```

Clean up:
- Remove Passport service provider
- Delete Passport migrations (or keep for historical data)
- Remove Passport routes from AuthServiceProvider

---

## From Custom JWT Implementation

### Assessment

Review your existing implementation:

1. **Algorithm used**: HS256, RS256, etc.
2. **Claims structure**: What claims are you using?
3. **Key storage**: Where are signing keys stored?
4. **Validation logic**: What checks are performed?

### Migration Steps

#### Step 1: Map Claims

| Your Claim | App Context Claim |
|------------|-------------------|
| `user_id` | `sub` |
| `channel` | `aud` |
| `tenant` | `tid` |
| `permissions` | `scp` |
| `device` | `did` |

#### Step 2: Update Token Generation

**Before:**

```php
$payload = [
    'user_id' => $user->id,
    'channel' => 'api',
    'permissions' => ['read', 'write'],
    'exp' => time() + 3600,
];

$token = JWT::encode($payload, $secret, 'HS256');
```

**After:**

```php
$claims = [
    'aud' => $context->getAppId(),
    'tid' => $tenantId,
    'scp' => ['api:read', 'api:write'],
];

$token = JWTAuth::claims($claims)->fromUser($user);
```

#### Step 3: Update Validation

Remove custom validation middleware and use app-context:

```php
// Before: Custom JWT middleware
// After: app-context middleware group
Route::middleware(['app-context'])->group(function () {
    // Routes
});
```

#### Step 4: Key Migration

If using HS256, you can continue or migrate to RS256:

**Keep HS256:**

```env
JWT_ALGO=HS256
JWT_SECRET=your-existing-secret
```

**Migrate to RS256:**

```bash
# Generate new RSA keys
openssl genrsa -out storage/jwt/private.pem 4096
openssl rsa -in storage/jwt/private.pem -pubout -out storage/jwt/public.pem
```

```env
JWT_ALGO=RS256
JWT_PUBLIC_KEY_PATH=storage/jwt/public.pem
JWT_PRIVATE_KEY_PATH=storage/jwt/private.pem
```

---

## Repository Migration

### From Config to Eloquent

When you outgrow config-based client storage:

#### Step 1: Create Database Tables

```bash
php artisan make:migration create_api_apps_table
php artisan make:migration create_api_app_keys_table
```

```php
// create_api_apps_table
Schema::create('api_apps', function (Blueprint $table) {
    $table->id();
    $table->string('app_code')->unique();
    $table->string('app_name');
    $table->string('description')->nullable();
    $table->string('owner_email')->nullable();
    $table->boolean('is_active')->default(true);
    $table->json('config')->nullable();
    $table->json('metadata')->nullable();
    $table->timestamps();
    $table->softDeletes();
});

// create_api_app_keys_table
Schema::create('api_app_keys', function (Blueprint $table) {
    $table->id();
    $table->foreignId('app_id')->constrained('api_apps')->cascadeOnDelete();
    $table->string('label')->nullable();
    $table->string('key_prefix', 20)->index();
    $table->string('key_hash');
    $table->json('scopes')->nullable();
    $table->json('config')->nullable();
    $table->timestamp('expires_at')->nullable();
    $table->timestamp('revoked_at')->nullable();
    $table->timestamp('last_used_at')->nullable();
    $table->string('last_used_ip')->nullable();
    $table->string('last_user_agent')->nullable();
    $table->timestamps();

    $table->index(['app_id', 'key_prefix']);
});
```

#### Step 2: Migrate Existing Clients

```php
// Migration script
$configClients = config('app-context.client_repository.config.clients');

foreach ($configClients as $appCode => $clientData) {
    $app = DB::table('api_apps')->insertGetId([
        'app_code' => $appCode,
        'app_name' => $clientData['name'],
        'is_active' => $clientData['is_active'] ?? true,
        'config' => json_encode([
            'channel' => $clientData['channel'],
            'tenant_id' => $clientData['tenant_id'] ?? null,
        ]),
        'metadata' => json_encode($clientData['metadata'] ?? []),
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    // Generate new key for database storage
    $repository = app(ClientRepositoryInterface::class);
    $keyData = $repository->generateKey();

    DB::table('api_app_keys')->insert([
        'app_id' => $app,
        'label' => 'Migrated from config',
        'key_prefix' => $keyData['prefix'],
        'key_hash' => $keyData['hash'],
        'config' => json_encode([
            'capabilities' => $clientData['capabilities'] ?? [],
            'ip_allowlist' => $clientData['ip_allowlist'] ?? [],
        ]),
        'expires_at' => $clientData['expires_at'] ?? null,
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    // IMPORTANT: Provide new key to client
    Log::info("Migrated client {$appCode}, new key: {$keyData['key']}");
}
```

#### Step 3: Update Configuration

```php
'client_repository' => [
    'driver' => 'eloquent',
    'eloquent' => [
        'apps_table' => 'api_apps',
        'app_keys_table' => 'api_app_keys',
        'hash_algorithm' => 'argon2id',
        'async_tracking' => true,
    ],
],
```

#### Step 4: Notify Clients

Since keys change during migration, notify all API clients of their new keys.

### From Legacy Single Table to Multi-Table

If using legacy `api_clients` table:

#### Step 1: Create New Tables

Create `api_apps` and `api_app_keys` tables as shown above.

#### Step 2: Migrate Data

```php
$legacyClients = DB::table('api_clients')->get();

foreach ($legacyClients as $legacy) {
    $app = DB::table('api_apps')->insertGetId([
        'app_code' => $legacy->app_code,
        'app_name' => $legacy->name,
        'is_active' => $legacy->is_active,
        'config' => json_encode([
            'channel' => $legacy->channel,
            'tenant_id' => $legacy->tenant_id,
        ]),
        'created_at' => $legacy->created_at,
        'updated_at' => $legacy->updated_at,
    ]);

    DB::table('api_app_keys')->insert([
        'app_id' => $app,
        'label' => 'Migrated from legacy',
        'key_prefix' => substr($legacy->key_hash, 0, 10), // If stored
        'key_hash' => $legacy->key_hash,
        'config' => $legacy->config,
        'expires_at' => $legacy->expires_at,
        'last_used_at' => $legacy->last_used_at,
        'last_used_ip' => $legacy->last_used_ip,
        'created_at' => $legacy->created_at,
        'updated_at' => $legacy->updated_at,
    ]);
}
```

#### Step 3: Update Configuration

Point to new tables:

```php
'eloquent' => [
    'apps_table' => 'api_apps',
    'app_keys_table' => 'api_app_keys',
    // Remove 'table' => 'api_clients'
],
```

---

## Version Upgrades

### v1.0.x to v1.1.x

#### New Features

- `route:channel` command for listing routes by channel
- `HttpExceptionInterface` implementation for better exception handling
- Improved rate limiting middleware

#### Breaking Changes

None. This is a minor version with backwards compatibility.

#### Upgrade Steps

```bash
composer update ronu/laravel-app-context
php artisan vendor:publish --tag=app-context-config --force
```

Review config changes and merge as needed.

### Future: v1.x to v2.x (Repository Pattern)

If you're using an older version before the repository pattern:

#### Breaking Changes

- Client storage abstracted behind `ClientRepositoryInterface`
- Configuration structure changed
- New middleware aliases (`app.requires`, `app.requires.all`)

#### Upgrade Steps

1. **Update package:**
   ```bash
   composer update ronu/laravel-app-context
   ```

2. **Publish new configuration:**
   ```bash
   php artisan vendor:publish --tag=app-context-config
   ```

3. **Update configuration:**
   - Move client definitions to `client_repository.config.clients`
   - Set `client_repository.driver` to `'config'` or `'eloquent'`

4. **Update middleware usage:**
   - `app.scope` is deprecated, use `app.requires`
   - `app.scope.all` is deprecated, use `app.requires.all`

5. **Test thoroughly** before deploying to production.

---

## Rollback Plan

If migration fails, have a rollback plan:

### Parallel Running

Run both systems during transition:

```php
// Check new system first, fall back to old
try {
    $context = app(AppContext::class);
    // Use new system
} catch (\Exception $e) {
    // Fall back to old system
    if (Auth::check()) {
        // Old auth logic
    }
}
```

### Feature Flags

Use feature flags to toggle between systems:

```php
if (config('features.use_app_context')) {
    Route::middleware(['app-context'])->group(/* new routes */);
} else {
    Route::middleware(['auth:api'])->group(/* old routes */);
}
```

### Database Backup

Always backup before migration:

```bash
# Backup database
pg_dump mydb > backup_before_migration.sql

# Backup config
cp config/app-context.php config/app-context.php.backup
```

---

## Support

For migration assistance:
- Review existing documentation
- Check GitHub issues for similar migrations
- Create a new issue with specific questions
