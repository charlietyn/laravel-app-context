# Code Examples

This document provides comprehensive code examples for common use cases with Laravel App Context.

## Table of Contents

1. [Dashboard Admin (SPA)](#dashboard-admin-spa)
2. [Mobile App](#mobile-app)
3. [Public Website](#public-website)
4. [B2B Partner API](#b2b-partner-api)
5. [Multi-Tenant Application](#multi-tenant-application)
6. [Custom Scopes System](#custom-scopes-system)
7. [Testing Examples](#testing-examples)
8. [Advanced Patterns](#advanced-patterns)

---

## Dashboard Admin (SPA)

Complete example for a single-page application admin dashboard.

### Channel Configuration

```php
// config/app-context.php
'channels' => [
    'admin' => [
        'subdomains' => ['admin', 'dashboard'],
        'path_prefixes' => ['/api'],
        'auth_mode' => 'jwt',
        'jwt_audience' => 'admin',
        'allowed_scopes' => [
            'admin:*',
            'admin:users:*',
            'admin:settings:*',
            'admin:reports:*',
        ],
        'rate_limit_profile' => 'admin',
        'tenant_mode' => 'multi',
        'audit' => [
            'enabled' => true,
            'log_all_requests' => true,
        ],
    ],
],

'rate_limits' => [
    'admin' => [
        'global' => '120/m',
        'by' => 'user',
        'endpoints' => [
            'POST:/api/export' => '5/h',
            'POST:/api/bulk-update' => '10/h',
        ],
    ],
],
```

### Routes

```php
// routes/api.php
use App\Http\Controllers\Admin\AuthController;
use App\Http\Controllers\Admin\UserController;
use App\Http\Controllers\Admin\SettingsController;
use App\Http\Controllers\Admin\ReportController;

// Login (without app.auth)
Route::middleware([
    'app.context',
    'app.throttle',
    'app.binding',
    'app.audit',
])->prefix('api')->group(function () {
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/password/forgot', [AuthController::class, 'forgotPassword']);
});

// Protected routes
Route::middleware(['app-context'])->prefix('api')->group(function () {
    // Auth
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/refresh', [AuthController::class, 'refresh']);
    Route::get('/me', [AuthController::class, 'me']);

    // Users
    Route::get('/users', [UserController::class, 'index'])
        ->middleware('app.requires:admin:users:read');
    Route::post('/users', [UserController::class, 'store'])
        ->middleware('app.requires:admin:users:create');
    Route::get('/users/{user}', [UserController::class, 'show'])
        ->middleware('app.requires:admin:users:read');
    Route::put('/users/{user}', [UserController::class, 'update'])
        ->middleware('app.requires:admin:users:update');
    Route::delete('/users/{user}', [UserController::class, 'destroy'])
        ->middleware('app.requires:admin:users:delete');

    // Settings (requires all scopes)
    Route::get('/settings', [SettingsController::class, 'index'])
        ->middleware('app.requires:admin:settings:read');
    Route::put('/settings', [SettingsController::class, 'update'])
        ->middleware('app.requires.all:admin:settings:read,admin:settings:write');

    // Reports
    Route::get('/reports/users', [ReportController::class, 'users'])
        ->middleware('app.requires:admin:reports:users');
    Route::get('/reports/activity', [ReportController::class, 'activity'])
        ->middleware('app.requires:admin:reports:activity');
    Route::post('/reports/export', [ReportController::class, 'export'])
        ->middleware('app.requires:admin:reports:export');
});
```

### AuthController

```php
<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Ronu\AppContext\Context\AppContext;

class AuthController extends Controller
{
    public function login(Request $request, AppContext $context): JsonResponse
    {
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string|min:8',
        ]);

        if (!Auth::attempt($credentials)) {
            return response()->json([
                'error' => 'AUTHENTICATION_FAILED',
                'message' => 'Invalid email or password',
            ], 401);
        }

        $user = Auth::user();

        // Check if user is admin
        if (!$user->hasRole('admin')) {
            Auth::logout();
            return response()->json([
                'error' => 'AUTHORIZATION_FAILED',
                'message' => 'Admin access required',
            ], 403);
        }

        // Build scopes from user permissions
        $scopes = $this->buildAdminScopes($user);

        // Create JWT with context binding
        $claims = [
            'aud' => $context->getAppId(),
            'tid' => $user->tenant_id,
            'scp' => $scopes,
        ];

        $token = JWTAuth::claims($claims)->fromUser($user);

        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => config('app-context.jwt.ttl'),
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'tenant_id' => $user->tenant_id,
            ],
            'scopes' => $scopes,
        ]);
    }

    public function logout(): JsonResponse
    {
        JWTAuth::invalidate(JWTAuth::getToken());

        return response()->json([
            'message' => 'Logged out successfully',
        ]);
    }

    public function refresh(): JsonResponse
    {
        $newToken = JWTAuth::refresh(JWTAuth::getToken());

        return response()->json([
            'access_token' => $newToken,
            'token_type' => 'Bearer',
            'expires_in' => config('app-context.jwt.ttl'),
        ]);
    }

    public function me(AppContext $context): JsonResponse
    {
        $user = User::find($context->getUserId());

        return response()->json([
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'tenant_id' => $context->getTenantId(),
            ],
            'scopes' => $context->getScopes(),
            'channel' => $context->getAppId(),
        ]);
    }

    private function buildAdminScopes(User $user): array
    {
        // Map user permissions to scopes
        $permissions = $user->getAllPermissions();
        $scopes = [];

        foreach ($permissions as $permission) {
            $scopes[] = "admin:{$permission->name}";
        }

        return $scopes;
    }
}
```

### UserController

```php
<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;
use Ronu\AppContext\Context\AppContext;

class UserController extends Controller
{
    public function index(AppContext $context, Request $request): AnonymousResourceCollection
    {
        $users = User::query()
            ->where('tenant_id', $context->getTenantId())
            ->when($request->search, fn($q, $s) => $q->where('name', 'like', "%{$s}%"))
            ->paginate($request->per_page ?? 15);

        return UserResource::collection($users);
    }

    public function store(AppContext $context, Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:8|confirmed',
            'role' => 'required|string|exists:roles,name',
        ]);

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => bcrypt($validated['password']),
            'tenant_id' => $context->getTenantId(),
        ]);

        $user->assignRole($validated['role']);

        return response()->json([
            'message' => 'User created successfully',
            'user' => new UserResource($user),
        ], 201);
    }

    public function show(AppContext $context, User $user): UserResource
    {
        // Ensure user belongs to same tenant
        if ($user->tenant_id !== $context->getTenantId()) {
            abort(404);
        }

        return new UserResource($user);
    }

    public function update(AppContext $context, Request $request, User $user): JsonResponse
    {
        if ($user->tenant_id !== $context->getTenantId()) {
            abort(404);
        }

        $validated = $request->validate([
            'name' => 'sometimes|string|max:255',
            'email' => 'sometimes|email|unique:users,email,' . $user->id,
            'role' => 'sometimes|string|exists:roles,name',
        ]);

        $user->update($validated);

        if (isset($validated['role'])) {
            $user->syncRoles([$validated['role']]);
        }

        return response()->json([
            'message' => 'User updated successfully',
            'user' => new UserResource($user),
        ]);
    }

    public function destroy(AppContext $context, User $user): JsonResponse
    {
        if ($user->tenant_id !== $context->getTenantId()) {
            abort(404);
        }

        // Prevent self-deletion
        if ($user->id === $context->getUserId()) {
            return response()->json([
                'error' => 'CANNOT_DELETE_SELF',
                'message' => 'Cannot delete your own account',
            ], 400);
        }

        $user->delete();

        return response()->json([
            'message' => 'User deleted successfully',
        ]);
    }
}
```

---

## Mobile App

Complete example for a mobile application with device binding.

### Channel Configuration

```php
// config/app-context.php
'channels' => [
    'mobile' => [
        'subdomains' => ['mobile', 'm', 'api-mobile'],
        'path_prefixes' => ['/mobile'],
        'auth_mode' => 'jwt',
        'jwt_audience' => 'mobile',
        'allowed_scopes' => [
            'mobile:*',
            'user:profile:*',
            'orders:*',
            'notifications:read',
        ],
        'rate_limit_profile' => 'mobile',
        'features' => [
            'push_notifications' => true,
            'offline_mode' => true,
        ],
    ],
],

'rate_limits' => [
    'mobile' => [
        'global' => '60/m',
        'authenticated_global' => '100/m',
        'by' => 'user_device',
        'burst' => '10/s',
        'endpoints' => [
            'POST:/mobile/orders' => '10/m',
            'POST:/mobile/checkout' => '5/m',
            'POST:/mobile/login' => '5/m',
        ],
    ],
],
```

### Routes

```php
// routes/api.php
use App\Http\Controllers\Mobile\AuthController;
use App\Http\Controllers\Mobile\ProfileController;
use App\Http\Controllers\Mobile\OrderController;
use App\Http\Controllers\Mobile\NotificationController;

// Public routes
Route::middleware([
    'app.context',
    'app.throttle',
])->prefix('mobile')->group(function () {
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/password/forgot', [AuthController::class, 'forgotPassword']);
});

// Protected routes
Route::middleware(['app-context'])->prefix('mobile')->group(function () {
    // Auth
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/refresh', [AuthController::class, 'refresh']);
    Route::post('/device/register', [AuthController::class, 'registerDevice']);

    // Profile
    Route::get('/profile', [ProfileController::class, 'show'])
        ->middleware('app.requires:user:profile:read');
    Route::put('/profile', [ProfileController::class, 'update'])
        ->middleware('app.requires:user:profile:update');
    Route::put('/profile/password', [ProfileController::class, 'updatePassword'])
        ->middleware('app.requires:user:profile:update');

    // Orders
    Route::get('/orders', [OrderController::class, 'index'])
        ->middleware('app.requires:orders:read');
    Route::post('/orders', [OrderController::class, 'store'])
        ->middleware('app.requires:orders:create');
    Route::get('/orders/{order}', [OrderController::class, 'show'])
        ->middleware('app.requires:orders:read');

    // Notifications
    Route::get('/notifications', [NotificationController::class, 'index'])
        ->middleware('app.requires:notifications:read');
    Route::put('/notifications/{id}/read', [NotificationController::class, 'markRead'])
        ->middleware('app.requires:notifications:read');
});
```

### AuthController with Device Binding

```php
<?php

namespace App\Http\Controllers\Mobile;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\UserDevice;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Ronu\AppContext\Context\AppContext;

class AuthController extends Controller
{
    public function login(Request $request, AppContext $context): JsonResponse
    {
        $validated = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
            'device_id' => 'required|string|max:255',
            'device_name' => 'nullable|string|max:255',
            'device_type' => 'nullable|in:ios,android',
            'push_token' => 'nullable|string',
        ]);

        if (!Auth::attempt($validated)) {
            return response()->json([
                'error' => 'AUTHENTICATION_FAILED',
                'message' => 'Invalid credentials',
            ], 401);
        }

        $user = Auth::user();

        // Register or update device
        $device = $this->registerDevice($user, $validated);

        // Build JWT with device binding
        $claims = [
            'aud' => $context->getAppId(),
            'did' => $device->device_id,
            'scp' => ['mobile:*', 'user:profile:*', 'orders:*', 'notifications:read'],
        ];

        $token = JWTAuth::claims($claims)->fromUser($user);
        $refreshToken = $this->generateRefreshToken($user, $device);

        return response()->json([
            'access_token' => $token,
            'refresh_token' => $refreshToken,
            'token_type' => 'Bearer',
            'expires_in' => config('app-context.jwt.ttl'),
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
            ],
        ]);
    }

    public function register(Request $request, AppContext $context): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:8|confirmed',
            'device_id' => 'required|string|max:255',
            'device_name' => 'nullable|string|max:255',
            'device_type' => 'nullable|in:ios,android',
        ]);

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => bcrypt($validated['password']),
        ]);

        $device = $this->registerDevice($user, $validated);

        $claims = [
            'aud' => $context->getAppId(),
            'did' => $device->device_id,
            'scp' => ['mobile:*', 'user:profile:*', 'orders:*', 'notifications:read'],
        ];

        $token = JWTAuth::claims($claims)->fromUser($user);
        $refreshToken = $this->generateRefreshToken($user, $device);

        return response()->json([
            'access_token' => $token,
            'refresh_token' => $refreshToken,
            'token_type' => 'Bearer',
            'expires_in' => config('app-context.jwt.ttl'),
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
            ],
        ], 201);
    }

    public function refresh(Request $request, AppContext $context): JsonResponse
    {
        $validated = $request->validate([
            'refresh_token' => 'required|string',
        ]);

        // Verify refresh token
        $device = UserDevice::where('refresh_token', hash('sha256', $validated['refresh_token']))
            ->where('user_id', $context->getUserId())
            ->first();

        if (!$device || $device->refresh_token_expires_at < now()) {
            return response()->json([
                'error' => 'INVALID_REFRESH_TOKEN',
                'message' => 'Invalid or expired refresh token',
            ], 401);
        }

        $user = $device->user;

        // Generate new tokens
        $claims = [
            'aud' => $context->getAppId(),
            'did' => $device->device_id,
            'scp' => $context->getScopes(),
        ];

        $newAccessToken = JWTAuth::claims($claims)->fromUser($user);
        $newRefreshToken = $this->generateRefreshToken($user, $device);

        // Invalidate old access token
        JWTAuth::invalidate(JWTAuth::getToken());

        return response()->json([
            'access_token' => $newAccessToken,
            'refresh_token' => $newRefreshToken,
            'token_type' => 'Bearer',
            'expires_in' => config('app-context.jwt.ttl'),
        ]);
    }

    public function logout(AppContext $context): JsonResponse
    {
        // Invalidate access token
        JWTAuth::invalidate(JWTAuth::getToken());

        // Clear device refresh token
        UserDevice::where('user_id', $context->getUserId())
            ->where('device_id', $context->getDeviceId())
            ->update([
                'refresh_token' => null,
                'refresh_token_expires_at' => null,
            ]);

        return response()->json([
            'message' => 'Logged out successfully',
        ]);
    }

    public function registerDevice(Request $request, AppContext $context): JsonResponse
    {
        $validated = $request->validate([
            'push_token' => 'required|string',
        ]);

        UserDevice::where('user_id', $context->getUserId())
            ->where('device_id', $context->getDeviceId())
            ->update([
                'push_token' => $validated['push_token'],
            ]);

        return response()->json([
            'message' => 'Device registered successfully',
        ]);
    }

    private function registerDevice(User $user, array $data): UserDevice
    {
        return UserDevice::updateOrCreate(
            [
                'user_id' => $user->id,
                'device_id' => $data['device_id'],
            ],
            [
                'device_name' => $data['device_name'] ?? 'Unknown Device',
                'device_type' => $data['device_type'] ?? 'unknown',
                'push_token' => $data['push_token'] ?? null,
                'last_used_at' => now(),
            ]
        );
    }

    private function generateRefreshToken(User $user, UserDevice $device): string
    {
        $token = Str::random(64);

        $device->update([
            'refresh_token' => hash('sha256', $token),
            'refresh_token_expires_at' => now()->addDays(14),
        ]);

        return $token;
    }
}
```

---

## Public Website

Example for a public website with optional authentication.

### Channel Configuration

```php
// config/app-context.php
'channels' => [
    'site' => [
        'subdomains' => ['www', null],
        'path_prefixes' => ['/site', '/'],
        'auth_mode' => 'jwt_or_anonymous',
        'jwt_audience' => 'site',
        'allowed_scopes' => [
            'site:*',
            'catalog:browse',
            'cart:*',
            'checkout:*',
            'user:profile:*',
        ],
        'public_scopes' => [
            'catalog:browse',
            'public:read',
        ],
        'anonymous_on_invalid_token' => false,
        'rate_limit_profile' => 'site',
        'audit' => [
            'enabled' => false,  // Less logging for public
        ],
    ],
],

'rate_limits' => [
    'site' => [
        'global' => '120/m',
        'by' => 'ip_or_user',
        'endpoints' => [
            'POST:/checkout' => '5/m',
            'POST:/contact' => '3/m',
        ],
    ],
],
```

### Routes

```php
// routes/web.php or routes/api.php
use App\Http\Controllers\Site\CatalogController;
use App\Http\Controllers\Site\CartController;
use App\Http\Controllers\Site\CheckoutController;
use App\Http\Controllers\Site\ProfileController;

Route::middleware(['app-context'])->group(function () {
    // Public routes (work without auth)
    Route::get('/products', [CatalogController::class, 'index']);
    Route::get('/products/{product}', [CatalogController::class, 'show']);
    Route::get('/categories', [CatalogController::class, 'categories']);

    // Cart (anonymous carts supported)
    Route::get('/cart', [CartController::class, 'show']);
    Route::post('/cart/items', [CartController::class, 'addItem']);
    Route::delete('/cart/items/{item}', [CartController::class, 'removeItem']);

    // Protected routes
    Route::get('/profile', [ProfileController::class, 'show'])
        ->middleware('app.requires:user:profile:read');
    Route::put('/profile', [ProfileController::class, 'update'])
        ->middleware('app.requires:user:profile:update');

    // Checkout (requires auth)
    Route::post('/checkout', [CheckoutController::class, 'process'])
        ->middleware('app.requires:checkout:process');
    Route::get('/orders', [CheckoutController::class, 'orders'])
        ->middleware('app.requires:user:profile:read');
});
```

### CatalogController

```php
<?php

namespace App\Http\Controllers\Site;

use App\Http\Controllers\Controller;
use App\Http\Resources\ProductResource;
use App\Models\Product;
use Illuminate\Http\Request;
use Ronu\AppContext\Context\AppContext;

class CatalogController extends Controller
{
    public function index(AppContext $context, Request $request)
    {
        $query = Product::query()
            ->where('is_active', true)
            ->with('category', 'images');

        // Personalization for authenticated users
        if ($context->isAuthenticated()) {
            $query->withUserWishlist($context->getUserId());
            $query->withUserPurchaseHistory($context->getUserId());
        }

        // Apply filters
        $query->when($request->category, fn($q, $c) => $q->where('category_id', $c))
            ->when($request->search, fn($q, $s) => $q->where('name', 'like', "%{$s}%"))
            ->when($request->min_price, fn($q, $p) => $q->where('price', '>=', $p))
            ->when($request->max_price, fn($q, $p) => $q->where('price', '<=', $p));

        $products = $query->paginate($request->per_page ?? 20);

        return ProductResource::collection($products)->additional([
            'meta' => [
                'authenticated' => $context->isAuthenticated(),
                'channel' => $context->getAppId(),
            ],
        ]);
    }

    public function show(AppContext $context, Product $product)
    {
        $product->load('category', 'images', 'reviews');

        // Add personalized data for authenticated users
        if ($context->isAuthenticated()) {
            $product->loadUserData($context->getUserId());
        }

        return new ProductResource($product);
    }
}
```

---

## B2B Partner API

Complete example for machine-to-machine API key authentication.

### Channel Configuration

```php
// config/app-context.php
'channels' => [
    'partner' => [
        'subdomains' => ['api-partners', 'partners'],
        'path_prefixes' => ['/partner'],
        'auth_mode' => 'api_key',
        'allowed_capabilities' => [
            'partner:*',
            'partner:orders:*',
            'partner:inventory:*',
            'partner:webhooks:*',
        ],
        'rate_limit_profile' => 'partner',
        'audit' => [
            'enabled' => true,
            'log_all_requests' => true,
            'include_request_body' => true,
        ],
    ],
],

'rate_limits' => [
    'partner' => [
        'global' => '600/m',
        'by' => 'client_id',
        'endpoints' => [
            'POST:/partner/bulk-import' => '10/h',
            'GET:/partner/*/export' => '20/h',
        ],
    ],
],

'client_repository' => [
    'driver' => 'config',
    'config' => [
        'hash_algorithm' => 'argon2id',
        'clients' => [
            'acme-corp' => [
                'name' => 'ACME Corporation',
                'key_hash' => '$argon2id$...',  // Generated hash
                'channel' => 'partner',
                'tenant_id' => null,  // Access to all tenants
                'capabilities' => [
                    'partner:orders:read',
                    'partner:orders:create',
                    'partner:inventory:read',
                ],
                'ip_allowlist' => [
                    '203.0.113.0/24',
                    '198.51.100.0/24',
                ],
                'is_active' => true,
                'metadata' => [
                    'tier' => 'premium',
                    'webhook_url' => 'https://acme.example.com/webhooks',
                ],
            ],
        ],
    ],
],
```

### Routes

```php
// routes/api.php
use App\Http\Controllers\Partner\OrderController;
use App\Http\Controllers\Partner\InventoryController;
use App\Http\Controllers\Partner\WebhookController;

Route::middleware(['app-context'])->prefix('partner')->group(function () {
    // Orders
    Route::get('/orders', [OrderController::class, 'index'])
        ->middleware('app.requires:partner:orders:read');
    Route::post('/orders', [OrderController::class, 'store'])
        ->middleware('app.requires:partner:orders:create');
    Route::get('/orders/{order}', [OrderController::class, 'show'])
        ->middleware('app.requires:partner:orders:read');
    Route::put('/orders/{order}/status', [OrderController::class, 'updateStatus'])
        ->middleware('app.requires:partner:orders:update');

    // Inventory
    Route::get('/inventory', [InventoryController::class, 'index'])
        ->middleware('app.requires:partner:inventory:read');
    Route::post('/inventory/bulk-update', [InventoryController::class, 'bulkUpdate'])
        ->middleware('app.requires:partner:inventory:update');
    Route::get('/inventory/{sku}', [InventoryController::class, 'show'])
        ->middleware('app.requires:partner:inventory:read');

    // Webhooks
    Route::get('/webhooks', [WebhookController::class, 'index'])
        ->middleware('app.requires:partner:webhooks:read');
    Route::post('/webhooks', [WebhookController::class, 'store'])
        ->middleware('app.requires:partner:webhooks:create');
    Route::delete('/webhooks/{webhook}', [WebhookController::class, 'destroy'])
        ->middleware('app.requires:partner:webhooks:delete');
});
```

### OrderController

```php
<?php

namespace App\Http\Controllers\Partner;

use App\Http\Controllers\Controller;
use App\Http\Resources\Partner\OrderResource;
use App\Models\Order;
use App\Services\OrderService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Ronu\AppContext\Context\AppContext;

class OrderController extends Controller
{
    public function __construct(
        private OrderService $orderService
    ) {}

    public function index(AppContext $context, Request $request)
    {
        $request->validate([
            'status' => 'nullable|in:pending,processing,shipped,delivered,cancelled',
            'from_date' => 'nullable|date',
            'to_date' => 'nullable|date|after_or_equal:from_date',
            'per_page' => 'nullable|integer|min:1|max:100',
        ]);

        $orders = Order::query()
            ->where('partner_id', $context->getClientId())
            ->when($request->status, fn($q, $s) => $q->where('status', $s))
            ->when($request->from_date, fn($q, $d) => $q->whereDate('created_at', '>=', $d))
            ->when($request->to_date, fn($q, $d) => $q->whereDate('created_at', '<=', $d))
            ->orderByDesc('created_at')
            ->paginate($request->per_page ?? 50);

        return OrderResource::collection($orders);
    }

    public function store(AppContext $context, Request $request): JsonResponse
    {
        $validated = $request->validate([
            'external_id' => 'required|string|max:255|unique:orders,external_id',
            'customer' => 'required|array',
            'customer.email' => 'required|email',
            'customer.name' => 'required|string',
            'customer.phone' => 'nullable|string',
            'items' => 'required|array|min:1',
            'items.*.sku' => 'required|string|exists:products,sku',
            'items.*.quantity' => 'required|integer|min:1',
            'items.*.price' => 'required|numeric|min:0',
            'shipping_address' => 'required|array',
            'shipping_address.line1' => 'required|string',
            'shipping_address.city' => 'required|string',
            'shipping_address.postal_code' => 'required|string',
            'shipping_address.country' => 'required|string|size:2',
            'metadata' => 'nullable|array',
        ]);

        $order = $this->orderService->createPartnerOrder(
            partnerId: $context->getClientId(),
            data: $validated
        );

        return response()->json([
            'message' => 'Order created successfully',
            'order' => new OrderResource($order),
        ], 201);
    }

    public function show(AppContext $context, Order $order): OrderResource
    {
        // Ensure order belongs to this partner
        if ($order->partner_id !== $context->getClientId()) {
            abort(404);
        }

        return new OrderResource($order->load('items', 'shipments'));
    }

    public function updateStatus(AppContext $context, Request $request, Order $order): JsonResponse
    {
        if ($order->partner_id !== $context->getClientId()) {
            abort(404);
        }

        $validated = $request->validate([
            'status' => 'required|in:processing,shipped,delivered,cancelled',
            'tracking_number' => 'required_if:status,shipped|string|max:255',
            'carrier' => 'required_if:status,shipped|string|max:100',
            'notes' => 'nullable|string|max:1000',
        ]);

        $this->orderService->updateStatus($order, $validated);

        return response()->json([
            'message' => 'Order status updated',
            'order' => new OrderResource($order->fresh()),
        ]);
    }
}
```

---

## Multi-Tenant Application

Example patterns for multi-tenant applications.

### Tenant Middleware (Additional)

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Ronu\AppContext\Context\AppContext;

class SetTenantScope
{
    public function handle(Request $request, Closure $next)
    {
        $context = app(AppContext::class);

        if ($tenantId = $context->getTenantId()) {
            // Set global scope for all models
            app()->instance('current_tenant_id', $tenantId);

            // Configure database connection for tenant
            config(['database.connections.tenant.database' => "tenant_{$tenantId}"]);
        }

        return $next($request);
    }
}
```

### Tenant-Aware Model

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

trait BelongsToTenant
{
    protected static function bootBelongsToTenant(): void
    {
        // Auto-scope queries
        static::addGlobalScope('tenant', function (Builder $builder) {
            if ($tenantId = app()->bound('current_tenant_id') ? app('current_tenant_id') : null) {
                $builder->where('tenant_id', $tenantId);
            }
        });

        // Auto-fill tenant_id on create
        static::creating(function (Model $model) {
            if (!$model->tenant_id && app()->bound('current_tenant_id')) {
                $model->tenant_id = app('current_tenant_id');
            }
        });
    }
}

// Usage
class Project extends Model
{
    use BelongsToTenant;
}
```

---

## Testing Examples

### Unit Test for AppContext

```php
<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ronu\AppContext\Context\AppContext;
use Ronu\AppContext\Exceptions\AuthorizationException;

class AppContextTest extends TestCase
{
    public function test_creates_context_from_channel(): void
    {
        $context = AppContext::fromChannel('admin', 'jwt', '127.0.0.1');

        $this->assertEquals('admin', $context->getAppId());
        $this->assertEquals('jwt', $context->getAuthMode());
        $this->assertEquals('127.0.0.1', $context->getIpAddress());
        $this->assertNull($context->getUserId());
    }

    public function test_immutable_modifications(): void
    {
        $original = AppContext::fromChannel('admin', 'jwt', '127.0.0.1');
        $modified = $original->withUserId(123);

        $this->assertNull($original->getUserId());
        $this->assertEquals(123, $modified->getUserId());
    }

    public function test_wildcard_scope_matching(): void
    {
        $context = AppContext::fromChannel('admin', 'jwt', '127.0.0.1')
            ->withScopes(['admin:*']);

        $this->assertTrue($context->hasScope('admin:users:read'));
        $this->assertTrue($context->hasScope('admin:settings'));
        $this->assertFalse($context->hasScope('mobile:users:read'));
    }

    public function test_requires_throws_on_missing_scope(): void
    {
        $context = AppContext::fromChannel('admin', 'jwt', '127.0.0.1')
            ->withScopes(['admin:users:read']);

        $this->expectException(AuthorizationException::class);
        $context->requires('admin:users:delete');
    }

    public function test_has_any_scope(): void
    {
        $context = AppContext::fromChannel('admin', 'jwt', '127.0.0.1')
            ->withScopes(['admin:users:read']);

        $this->assertTrue($context->hasAnyScope(['admin:users:read', 'admin:users:write']));
        $this->assertFalse($context->hasAnyScope(['admin:settings', 'mobile:*']));
    }
}
```

### Feature Test for Authentication

```php
<?php

namespace Tests\Feature;

use App\Models\User;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Tests\TestCase;

class AuthenticationTest extends TestCase
{
    public function test_login_returns_jwt(): void
    {
        $user = User::factory()->create([
            'password' => bcrypt('password'),
        ]);

        $response = $this->postJson('/api/login', [
            'email' => $user->email,
            'password' => 'password',
        ]);

        $response->assertOk()
            ->assertJsonStructure([
                'access_token',
                'token_type',
                'expires_in',
            ]);
    }

    public function test_protected_endpoint_requires_auth(): void
    {
        $response = $this->getJson('/api/users');

        $response->assertStatus(401);
    }

    public function test_authenticated_request_succeeds(): void
    {
        $user = User::factory()->create();
        $token = JWTAuth::claims([
            'aud' => 'admin',
            'scp' => ['admin:users:read'],
        ])->fromUser($user);

        $response = $this->withHeader('Authorization', "Bearer {$token}")
            ->getJson('/api/users');

        $response->assertOk();
    }

    public function test_wrong_audience_rejected(): void
    {
        $user = User::factory()->create();
        $token = JWTAuth::claims([
            'aud' => 'mobile',  // Wrong audience
        ])->fromUser($user);

        $response = $this->withHeader('Authorization', "Bearer {$token}")
            ->getJson('/api/users');  // Admin channel

        $response->assertStatus(403)
            ->assertJson(['error' => 'CONTEXT_BINDING_FAILED']);
    }

    public function test_missing_scope_rejected(): void
    {
        $user = User::factory()->create();
        $token = JWTAuth::claims([
            'aud' => 'admin',
            'scp' => ['admin:reports:read'],  // No users scope
        ])->fromUser($user);

        $response = $this->withHeader('Authorization', "Bearer {$token}")
            ->getJson('/api/users');

        $response->assertStatus(403)
            ->assertJson(['error' => 'AUTHORIZATION_FAILED']);
    }
}
```

### API Key Test

```php
<?php

namespace Tests\Feature;

use Tests\TestCase;

class ApiKeyAuthenticationTest extends TestCase
{
    public function test_api_key_authentication(): void
    {
        // Assuming config driver with test client
        config([
            'app-context.client_repository.config.clients.test-partner' => [
                'name' => 'Test Partner',
                'key_hash' => bcrypt('test-api-key'),
                'channel' => 'partner',
                'capabilities' => ['partner:inventory:read'],
                'is_active' => true,
            ],
        ]);

        $response = $this->withHeaders([
            'X-Client-Id' => 'test-partner',
            'X-Api-Key' => 'test-api-key',
        ])->getJson('/partner/inventory');

        $response->assertOk();
    }

    public function test_invalid_api_key_rejected(): void
    {
        $response = $this->withHeaders([
            'X-Client-Id' => 'test-partner',
            'X-Api-Key' => 'wrong-key',
        ])->getJson('/partner/inventory');

        $response->assertStatus(401);
    }
}
```

---

## Advanced Patterns

### Custom Scope Resolver

```php
<?php

namespace App\Support;

use App\Models\User;
use Ronu\AppContext\Context\AppContext;

class ScopeResolver
{
    public function resolveUserScopes(User $user, AppContext $context): array
    {
        $scopes = [];

        // Base scopes from roles
        foreach ($user->roles as $role) {
            $scopes[] = "role:{$role->name}";

            foreach ($role->permissions as $permission) {
                $scopes[] = "{$context->getAppId()}:{$permission->name}";
            }
        }

        // Channel-specific scopes
        $channelScopes = config("app-context.channels.{$context->getAppId()}.allowed_scopes", []);
        $scopes = array_intersect($scopes, $this->expandWildcards($channelScopes));

        return array_unique($scopes);
    }

    private function expandWildcards(array $scopes): array
    {
        // Expand admin:* to match any admin:xxx scope
        return $scopes;  // Implementation depends on requirements
    }
}
```

### Event-Driven Context Logging

```php
<?php

namespace App\Listeners;

use App\Events\OrderCreated;
use Illuminate\Support\Facades\Log;
use Ronu\AppContext\Context\AppContext;

class LogOrderCreation
{
    public function handle(OrderCreated $event): void
    {
        $context = app(AppContext::class);

        Log::channel('orders')->info('Order created', [
            'order_id' => $event->order->id,
            'total' => $event->order->total,
            ...$context->toLogContext(),
        ]);
    }
}
```

### Context-Aware Repository

```php
<?php

namespace App\Repositories;

use App\Models\Project;
use Illuminate\Database\Eloquent\Collection;
use Ronu\AppContext\Context\AppContext;

class ProjectRepository
{
    public function __construct(
        private AppContext $context
    ) {}

    public function all(): Collection
    {
        return Project::query()
            ->where('tenant_id', $this->context->getTenantId())
            ->get();
    }

    public function find(int $id): ?Project
    {
        return Project::query()
            ->where('tenant_id', $this->context->getTenantId())
            ->find($id);
    }

    public function create(array $data): Project
    {
        return Project::create([
            ...$data,
            'tenant_id' => $this->context->getTenantId(),
            'created_by' => $this->context->getUserId(),
        ]);
    }
}
```

---

This concludes the code examples. For more information, see the main [README](README.md) and [Architecture](ARCHITECTURE.md) documentation.
