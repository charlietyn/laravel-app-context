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

## 401 "API key required"

**Cause**: API key authentication is required but headers are missing.

**Fix**:
- Provide `X-Client-Id` and `X-Api-Key` headers (or custom header names).

## 403 "Token audience mismatch"

**Cause**: JWT `aud` does not match the resolved channel.

**Fix**:
- Ensure tokens are minted with channel-appropriate audiences.

## 429 "Too Many Attempts"

**Cause**: Rate limit profile reached.

**Fix**:
- Adjust `rate_limits` for the channel or endpoint.

## JWT RSA keys missing in dev

**Cause**: RSA keys are missing and dev fallback is disabled.

**Fix**:
- Provide RSA keys at configured paths, or enable dev fallback in development.

[Back to index](../index.md)
