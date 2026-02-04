# Edge and extreme scenarios

## 1) Config caching hides updated channel rules

**Symptom**
- Requests still resolve to old channels after editing `config/app-context.php`.

**Cause**
- Laravel config cache is stale.

**Mitigation**
- Clear and rebuild config cache when deploying config changes.

**How to reproduce**
1. Run `php artisan config:cache`.
2. Change `channels` or `detection_strategy` in config.
3. Observe unchanged behavior.

**How to test**
- Clear cache (`php artisan config:clear`) and confirm new behavior.

---

## 2) Long-running queue workers lack AppContext

**Symptom**
- Jobs fail when calling `app(AppContext::class)` or using context-based scopes.

**Cause**
- `AppContext` is resolved per HTTP request. Queue workers do not have an HTTP request scope.

**Mitigation**
- Pass the required context data into jobs explicitly (e.g., channel, tenant, user ID).

**How to reproduce**
1. Dispatch a job that calls `app(AppContext::class)`.
2. Observe `null` context or missing data.

**How to test**
- Update job payload to include `app_id`, `tenant_id`, `user_id` and use them directly.

---

## 3) Concurrent JWT refresh/blacklist race

**Symptom**
- Users see intermittent `Token has been blacklisted` errors during token refresh.

**Cause**
- Refresh and blacklist checks can overlap under concurrency.

**Mitigation**
- Use `jwt.blacklist_grace_period` and ensure cache store is configured for blacklist usage.

**How to reproduce**
1. Refresh tokens concurrently from multiple devices.
2. Observe intermittent blacklist errors.

**How to test**
- Increase `blacklist_grace_period` and repeat concurrent refresh requests.

---

## 4) Rate limiting spikes under burst traffic

**Symptom**
- `429 Too Many Attempts` responses during short traffic spikes.

**Cause**
- `burst` and `global` limits are too low for the channel or endpoint.

**Mitigation**
- Adjust `rate_limits.{profile}.burst` and `rate_limits.{profile}.global` for the affected channel.

**How to reproduce**
1. Send a burst of requests to a throttled endpoint.
2. Observe 429 responses.

**How to test**
- Increase burst settings and confirm successful responses.

---

## 5) Tenant mismatch in multi-tenant channels

**Symptom**
- 403 responses with tenant binding errors.

**Cause**
- `tenant_mode` is `multi` and the request does not include the tenant ID or it does not match the token/client.

**Mitigation**
- Ensure tenant IDs are passed via route param, header (`X-Tenant-Id`), or query string.

**How to reproduce**
1. Configure a channel with `tenant_mode: multi`.
2. Call a route without tenant ID.

**How to test**
- Include a matching tenant ID in the request and confirm access.

---

## 6) API key IP allowlist and reverse proxies

**Symptom**
- Valid API keys fail with `IP not allowed` behind a proxy or load balancer.

**Cause**
- The request IP is the proxy IP, not the client IP.

**Mitigation**
- Configure Laravel trusted proxies so `$request->ip()` reflects the real client IP.

**How to reproduce**
1. Send requests through a proxy without trusted proxy config.
2. Observe allowlist failure.

**How to test**
- Configure trusted proxies and verify allowlist passes.

---

## 7) Audit logging of large payloads

**Symptom**
- Large responses are not logged or logs become heavy.

**Cause**
- Response body logging only captures small payloads; large payloads can bloat logs.

**Mitigation**
- Disable `include_response_body` or log selectively; keep response bodies small for audit logs.

**How to reproduce**
1. Enable `audit.include_response_body`.
2. Return a large response.

**How to test**
- Disable response body logging and confirm log size stabilizes.

---

## 8) RSA JWT keys missing in non-dev environments

**Symptom**
- JWT verification fails in production when RSA keys are missing.

**Cause**
- Dev fallback only runs in configured dev environments. Non-dev environments will not fall back.

**Mitigation**
- Ensure RSA key paths exist and are readable, or use HS256 explicitly.

**How to reproduce**
1. Configure `JWT_ALGO=RS256` in production.
2. Remove RSA keys.

**How to test**
- Add RSA keys and verify JWT validation succeeds.

## Evidence
- File: src/Context/ContextResolver.php
  - Symbol: ContextResolver::resolve(), ContextResolver::getDetectionStrategy()
  - Notes: Drives channel resolution, impacted by config caching.
- File: src/AppContextServiceProvider.php
  - Symbol: AppContextServiceProvider::configureJwtFallback()
  - Notes: Dev-only fallback when RSA keys are missing.
- File: src/Auth/Verifiers/JwtVerifier.php
  - Symbol: JwtVerifier::postVerify(), JwtVerifier::canRefresh()
  - Notes: Blacklist checks and refresh window handling.
- File: src/Middleware/RateLimitByContext.php
  - Symbol: RateLimitByContext::handle(), RateLimitByContext::getRateLimitConfig()
  - Notes: Applies burst/global rate limits.
- File: src/Middleware/EnforceContextBinding.php
  - Symbol: EnforceContextBinding::validateTenantBinding()
  - Notes: Enforces tenant binding for multi-tenant channels.
- File: src/Auth/Verifiers/ApiKeyVerifier.php
  - Symbol: ApiKeyVerifier::isIpAllowed(), ApiKeyVerifier::verify()
  - Notes: Enforces IP allowlists.
- File: src/Middleware/InjectAuditContext.php
  - Symbol: InjectAuditContext::logResponse()
  - Notes: Response body logging behavior and size limitations.
