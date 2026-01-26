# Security Guide

This document provides comprehensive security guidance for Laravel App Context, including threat models, secure configuration, and best practices.

## Table of Contents

1. [Security Overview](#security-overview)
2. [Threat Model](#threat-model)
3. [JWT Security](#jwt-security)
4. [API Key Security](#api-key-security)
5. [Channel Security](#channel-security)
6. [Multi-Tenant Security](#multi-tenant-security)
7. [Rate Limiting](#rate-limiting)
8. [Audit Logging](#audit-logging)
9. [Production Checklist](#production-checklist)
10. [Incident Response](#incident-response)

---

## Security Overview

Laravel App Context implements defense-in-depth security with multiple layers of protection:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Security Layers                                   │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 1: Transport Security                                          │
│ - HTTPS only (enforced at load balancer)                            │
│ - TLS 1.2+ required                                                 │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 2: Rate Limiting                                              │
│ - Per-channel limits                                                │
│ - Per-endpoint limits                                               │
│ - Burst protection                                                  │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 3: Authentication                                             │
│ - JWT verification (algorithm, signature, claims)                   │
│ - API Key verification (hash, IP allowlist, expiration)             │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 4: Context Binding                                            │
│ - Audience validation (channel binding)                             │
│ - Tenant validation (tenant binding)                                │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 5: Authorization                                              │
│ - Scope/capability checking                                         │
│ - Resource-level access control                                     │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 6: Audit                                                      │
│ - Request logging                                                   │
│ - Authentication failure logging                                    │
│ - Anomaly detection                                                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Threat Model

### Threat Categories

| Category | Threat | Mitigation |
|----------|--------|------------|
| **Authentication** | Token theft | Short TTL, blacklist, device binding |
| **Authentication** | Algorithm confusion | Strict algorithm whitelist |
| **Authentication** | Brute force | Rate limiting, account lockout |
| **Authorization** | Token reuse | Audience binding |
| **Authorization** | Privilege escalation | Scope restrictions per channel |
| **Data** | Cross-tenant access | Tenant binding in JWT |
| **Data** | Information disclosure | Audit logging, minimal error details |
| **Availability** | DoS attacks | Rate limiting, burst limits |
| **API Keys** | Key compromise | IP allowlist, key rotation |

### Attack Vectors

**1. JWT Algorithm Confusion (CVE-2015-9235)**

Attack: Attacker changes algorithm to `none` to bypass signature verification.

Protection:
```php
// Hard-coded algorithm whitelist in JwtVerifier
private const ALLOWED_ALGORITHMS = ['HS256', 'RS256', 'RS384', 'RS512'];

// Pre-verification rejects 'none'
if (strtolower($algorithm) === 'none') {
    Log::warning('JWT none algorithm attack attempt', ['ip' => $ip]);
    throw AuthenticationException::algorithmMismatch('none');
}
```

**2. Token Replay Attack**

Attack: Attacker captures valid token and uses it for different channel.

Protection:
```php
// Audience binding in EnforceContextBinding middleware
if ($tokenAudience !== $context->getAppId()) {
    throw ContextBindingException::audienceMismatch(
        expected: $context->getAppId(),
        actual: $tokenAudience
    );
}
```

**3. Cross-Tenant Access**

Attack: User accesses resources from different tenant.

Protection:
```php
// Tenant binding validation
if ($tokenTenant !== $requestTenant) {
    throw ContextBindingException::tenantMismatch(
        expected: $requestTenant,
        actual: $tokenTenant
    );
}
```

**4. API Key Compromise**

Attack: Attacker obtains valid API key.

Protection:
- IP allowlist restricts key usage to specific IPs
- Key expiration limits exposure window
- Key revocation for immediate invalidation
- Usage tracking for anomaly detection

---

## JWT Security

### Algorithm Configuration

**Production (Recommended):**

```php
'jwt' => [
    'algorithm' => 'RS256',  // Asymmetric algorithm
    'public_key_path' => env('JWT_PUBLIC_KEY_PATH'),
    'private_key_path' => env('JWT_PRIVATE_KEY_PATH'),
    'allowed_algorithms' => ['RS256', 'RS384', 'RS512'],
],
```

**Why RS256?**
- Asymmetric: Private key never leaves auth server
- Public key can be distributed to verification services
- Prevents HMAC key confusion attacks

### Key Generation

```bash
# Generate 4096-bit RSA key pair
mkdir -p storage/jwt
openssl genrsa -out storage/jwt/private.pem 4096
openssl rsa -in storage/jwt/private.pem -pubout -out storage/jwt/public.pem

# Set restrictive permissions
chmod 600 storage/jwt/private.pem
chmod 644 storage/jwt/public.pem
```

### Key Rotation

1. Generate new key pair
2. Update configuration to use new keys
3. Keep old public key for verifying existing tokens
4. After max token lifetime, remove old public key

### Token Claims

**Required Claims:**

| Claim | Purpose | Validation |
|-------|---------|------------|
| `sub` | User identifier | Must exist |
| `exp` | Expiration time | Must be future |
| `iat` | Issued at | Must be past |
| `aud` | Audience (channel) | Must match channel |

**Recommended Claims:**

| Claim | Purpose |
|-------|---------|
| `jti` | Unique token ID (for blacklist) |
| `tid` | Tenant ID (multi-tenant) |
| `scp` | Scopes array |
| `did` | Device ID (mobile) |

### Token Blacklist

Enable blacklist for token invalidation:

```php
'jwt' => [
    'blacklist_enabled' => true,
    'blacklist_grace_period' => 30,  // Seconds for race conditions
],
```

**Blacklist Implementation:**

```php
// On logout
JWTAuth::invalidate(JWTAuth::getToken());

// In JwtVerifier
if (Cache::has("jwt_blacklist:{$jti}")) {
    throw AuthenticationException::blacklistedToken();
}
```

### Development Fallback

**Only for development environments:**

```php
'dev_fallback' => [
    'enabled' => env('JWT_DEV_FALLBACK', false),
    'algorithm' => 'HS256',
    'secret' => env('JWT_DEV_SECRET', env('APP_KEY')),
],
```

**Security Warning:** Never enable in production. The fallback uses symmetric signing which is less secure.

---

## API Key Security

### Hash Algorithm

**Always use Argon2id:**

```php
'api_key' => [
    'hash_algorithm' => 'argon2id',  // Recommended
],
```

**Why Argon2id?**
- Memory-hard: Resistant to GPU/ASIC attacks
- Balances time and memory cost
- Winner of Password Hashing Competition

**Argon2id Parameters (PHP defaults):**
- Memory cost: 65536 bytes (64 MB)
- Time cost: 4 iterations
- Parallelism: 3 threads

### Key Format

API keys use format: `{prefix}.{secret}`

```
aBcDeFgHiJ.1234567890abcdefghijklmnopqrstuvwxyz
└────┬────┘ └──────────────────┬────────────────┘
  Prefix              Secret (hashed)
 (stored)
```

**Benefits:**
- Prefix enables database lookup without decryption
- Secret is hashed (never stored in plaintext)
- Prefix can be logged safely for debugging

### IP Allowlist

Restrict API key usage to specific IPs:

```php
'ip_allowlist' => [
    '203.0.113.0/24',     // CIDR notation
    '198.51.100.42',      // Single IP
    '2001:db8::/32',      // IPv6
],
```

**Validation:**

```php
private function isIpAllowed(string $ip, array $allowlist): bool
{
    foreach ($allowlist as $allowed) {
        if (str_contains($allowed, '/')) {
            // CIDR check
            if ($this->ipInCidr($ip, $allowed)) {
                return true;
            }
        } else {
            // Exact match
            if ($ip === $allowed) {
                return true;
            }
        }
    }
    return false;
}
```

### Key Expiration

Set expiration dates for API keys:

```php
'expires_at' => '2025-12-31 23:59:59',
```

**Validation in ApiKeyVerifier:**

```php
if ($client->isExpired()) {
    throw AuthenticationException::expiredApiKey();
}
```

### Key Rotation

**Rotation Process:**

1. Generate new key with different prefix
2. Notify client of new key
3. Set grace period where both keys work
4. Revoke old key after transition

**Configuration:**

```php
'api_key' => [
    'rotation_days' => 90,
    'expiration_warning_days' => 15,
    'max_keys_per_client' => 5,
],
```

### Key Generation

```php
$repository = app(ClientRepositoryInterface::class);
$keyData = $repository->generateKey();

// $keyData = [
//     'key' => 'aBcDeFgHiJ.1234567890abcdefghijklmnopqrstuvwxyz',
//     'hash' => '$argon2id$v=19$m=65536,t=4,p=3$...',
//     'prefix' => 'aBcDeFgHiJ',
// ]
```

---

## Channel Security

### Deny by Default

Always enable in production:

```php
'deny_by_default' => true,
```

This rejects requests that don't match any configured channel.

### Channel Detection

**Never trust client headers for channel detection:**

```php
// BAD: Client can spoof channel
$channel = $request->header('X-Channel');

// GOOD: Derive from host/path (server-controlled)
$channel = $this->resolver->resolve($request)->getAppId();
```

### Auth Mode Restrictions

Configure appropriate auth mode per channel:

| Channel | Auth Mode | Rationale |
|---------|-----------|-----------|
| `mobile` | `jwt` | User authentication required |
| `admin` | `jwt` | Strict user auth, audit trail |
| `partner` | `api_key` | Machine-to-machine, no users |
| `site` | `jwt_or_anonymous` | Public content with optional auth |

### Scope Restrictions

Limit scopes per channel:

```php
'admin' => [
    'allowed_scopes' => ['admin:*'],  // Only admin scopes
],

'mobile' => [
    'allowed_scopes' => ['mobile:*', 'user:profile:*'],  // Limited scopes
],
```

---

## Multi-Tenant Security

### Tenant Binding

Enable tenant enforcement:

```php
'security' => [
    'enforce_tenant_binding' => true,
],
```

### JWT Tenant Claim

Include tenant in JWT:

```php
$claims = [
    'tid' => $tenantId,  // Tenant binding
    // ...
];
```

### Tenant Extraction

Middleware extracts tenant from multiple sources:

```php
private function extractRequestTenant(Request $request): ?string
{
    // 1. Route parameter
    if ($tenant = $request->route('tenant_id')) {
        return $tenant;
    }

    // 2. Header
    if ($tenant = $request->header('X-Tenant-Id')) {
        return $tenant;
    }

    // 3. Query parameter
    if ($tenant = $request->query('tenant_id')) {
        return $tenant;
    }

    return null;
}
```

### Tenant Isolation in Queries

```php
public function index(AppContext $context)
{
    return User::query()
        ->where('tenant_id', $context->getTenantId())
        ->get();
}
```

---

## Rate Limiting

### Configuration

```php
'rate_limits' => [
    'mobile' => [
        'global' => '60/m',
        'authenticated_global' => '100/m',
        'by' => 'user_device',
        'burst' => '10/s',
        'endpoints' => [
            'POST:/mobile/login' => '5/m',     // Login brute force protection
            'POST:/mobile/checkout' => '5/m',  // Fraud prevention
        ],
    ],
],
```

### Rate Limit Strategies

| Strategy | Use Case |
|----------|----------|
| `user` | Prevent single user abuse |
| `ip` | Prevent anonymous abuse |
| `client_id` | Limit API client requests |
| `user_device` | Per-device limits (mobile) |

### Brute Force Protection

Login endpoints should have strict limits:

```php
'endpoints' => [
    'POST:/*/login' => '5/m',
    'POST:/*/password/reset' => '3/m',
    'POST:/*/register' => '3/m',
],
```

---

## Audit Logging

### Configuration

```php
'audit' => [
    'enabled' => true,
    'log_channel' => 'security',  // Dedicated channel
    'log_failed_auth' => true,
    'log_all_requests' => false,  // Enable for compliance
    'sensitive_headers' => [
        'Authorization',
        'X-Api-Key',
        'Cookie',
        'X-CSRF-Token',
    ],
],
```

### Log Context

Every log entry includes:

```php
Log::shareContext([
    'app_id' => $context->getAppId(),
    'auth_mode' => $context->getAuthMode(),
    'user_id' => $context->getUserId(),
    'client_id' => $context->getClientId(),
    'tenant_id' => $context->getTenantId(),
    'device_id' => $context->getDeviceId(),
    'ip_address' => $context->getIpAddress(),
    'request_id' => $context->getRequestId(),
]);
```

### Security Events to Log

| Event | Log Level | Details |
|-------|-----------|---------|
| Authentication failure | Warning | IP, user agent, reason |
| Invalid algorithm | Warning | Algorithm attempted |
| Audience mismatch | Warning | Expected vs actual |
| Tenant mismatch | Warning | Expected vs actual |
| IP not allowed | Warning | Client ID, IP |
| Token blacklisted | Info | JTI |
| Rate limit exceeded | Warning | Key, limit |

### Log Storage

- Use dedicated log channel for security events
- Consider SIEM integration (Splunk, ELK, etc.)
- Retain logs per compliance requirements
- Encrypt logs at rest

---

## Production Checklist

### Pre-Deployment

- [ ] **deny_by_default = true**
- [ ] **JWT using RS256** with unique keys per environment
- [ ] **verify_aud = true** for JWT audience validation
- [ ] **verify_iss = true** for JWT issuer validation
- [ ] **blacklist_enabled = true** with Redis backend
- [ ] **API keys hashed with Argon2id**
- [ ] **IP allowlists configured** for critical partners
- [ ] **Rate limits configured** per channel
- [ ] **Audit logging enabled**
- [ ] **HTTPS enforced** at load balancer
- [ ] **TLS 1.2+ required**
- [ ] **JWT keys stored securely** (not in git)
- [ ] **Environment variables** for all secrets
- [ ] **Error messages** don't leak sensitive info

### Security Headers

Configure in web server or middleware:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

### Monitoring

- [ ] Alert on authentication failure spikes
- [ ] Alert on rate limit threshold approaches
- [ ] Monitor API key expiration dates
- [ ] Track unusual IP patterns
- [ ] Monitor token blacklist size

---

## Incident Response

### Token Compromise

1. **Immediate:** Blacklist the token
   ```php
   JWTAuth::setToken($compromisedToken)->invalidate();
   ```

2. **Assess:** Review audit logs for unauthorized access

3. **Contain:** If widespread, rotate JWT signing keys

4. **Notify:** Inform affected users

### API Key Compromise

1. **Immediate:** Revoke the key
   ```php
   $repository->revoke($clientId);
   ```

2. **Assess:** Review usage logs for unauthorized requests

3. **Generate:** Issue new key to legitimate client

4. **Notify:** Inform the partner

### Mass Attack Detection

1. **Detect:** Unusual rate limit violations
2. **Block:** Add IPs to WAF/firewall
3. **Analyze:** Review attack patterns
4. **Harden:** Adjust rate limits if needed

### Key Rotation (Planned)

1. Generate new keys
2. Deploy new keys to auth server
3. Monitor for issues
4. After max token TTL, remove old keys

---

## Security Contacts

For security vulnerabilities, please email: security@example.com

Do not report security issues via public GitHub issues.
