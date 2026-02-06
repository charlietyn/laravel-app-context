# Troubleshooting

## 403 "Request does not match any configured channel"

**Cause**: `deny_by_default` is enabled and the request does not match any channel.

**Fix**:
- Ensure `channels` includes matching `subdomains` or `path_prefixes`.
- Or disable deny-by-default for development.

## 401 "Authentication required"

**Cause**: JWT is required but missing from the request.

**Fix**:
- Provide a valid `Authorization: Bearer <token>` header (or configured token source).
- If your channel is `jwt_or_anonymous`, add `app.auth.required:jwt` to force token on sensitive routes.

## 403 "Missing Required Permission" when token is missing

**Cause**:
- Route uses `app.scope:*`.
- Channel is `jwt_or_anonymous` and request became anonymous.
- Authorization fails (403) before a strict auth requirement is declared.

**Fix**:
- Add `app.auth.required:jwt` before/alongside scope middleware on private routes.
- Keep public routes under plain `app-context`.

## 401 "API key required"

**Cause**: API key authentication is required but headers are missing.

**Fix**:
- Provide `X-Client-Id` and `X-Api-Key` headers (or custom header names).
- For machine-only routes in mixed channels, use `app.auth.required:api_key`.

## 403 "Token audience mismatch"

**Cause**: JWT `aud` does not match the resolved channel.

**Fix**:
- Ensure tokens are minted with channel-appropriate audiences.

## 429 "Too Many Attempts"

**Cause**: Rate limit profile reached.

**Fix**:
- Adjust `rate_limits` for the channel or endpoint.

## "Auth guard [app-context] is not defined"

**Important first check**:
- If you are using `app.auth.required` / `ctx.auth.required`, you can ignore this section (guard is not required).
- This error only applies when you use Laravel middleware `auth:app-context`.

**Cause**: Guard is not declared in `config/auth.php`.

**Fix (only for `auth:app-context`)**:
1. Add guard config:
   ```php
   'guards' => [
       'app-context' => [
           'driver' => 'app-context',
           'provider' => 'users',
       ],
   ],
   ```
2. Refresh config cache:
   ```bash
   php artisan optimize:clear
   php artisan config:cache
   ```

## JWT RSA keys missing in dev

**Cause**: RSA keys are missing and dev fallback is disabled.

**Fix**:
- Provide RSA keys at configured paths, or enable dev fallback in development.

[Back to index](../index.md)
