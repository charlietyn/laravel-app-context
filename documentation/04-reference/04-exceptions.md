# Exceptions

Laravel App Context ships custom exceptions that extend `AppContextException` and render JSON error responses.

## `AppContextException`
Base exception with:
- `getErrorCode()`
- `getHttpStatus()`
- `render()` (JSON response)

## `AuthenticationException`
Thrown when authentication fails:
- Missing JWT or API key
- Invalid/expired/blacklisted token
- Invalid or revoked API key
- IP allowlist failure

## `AuthorizationException`
Thrown when required scopes/capabilities are missing.

## `ContextBindingException`
Thrown when:
- JWT audience does not match the channel
- Tenant binding fails
- No channel matched and `deny_by_default` is enabled

## Evidence
- File: src/Exceptions/AppContextException.php
  - Symbol: AppContextException::render(), AppContextException::getHttpStatus()
  - Notes: Base exception behavior and JSON response.
- File: src/Exceptions/AuthenticationException.php
  - Symbol: AuthenticationException::missingToken(), AuthenticationException::invalidApiKey()
  - Notes: Authentication failure variants.
- File: src/Exceptions/AuthorizationException.php
  - Symbol: AuthorizationException::missingAnyPermission()
  - Notes: Authorization failure variants.
- File: src/Exceptions/ContextBindingException.php
  - Symbol: ContextBindingException::audienceMismatch(), ContextBindingException::denyByDefault()
  - Notes: Context binding failure variants.
