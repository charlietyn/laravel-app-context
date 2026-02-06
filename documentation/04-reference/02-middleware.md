# Middleware

The service provider registers the following aliases and middleware group:

## Middleware group

| Group | Pipeline |
| --- | --- |
| `app-context` | `ResolveAppContext` → `RateLimitByContext` → `AuthenticateChannel` → `EnforceContextBinding` → `InjectAuditContext` |


## Execution order and responsibility

For the `app-context` group, request entry order is:
1. `ResolveAppContext`
2. `RateLimitByContext`
3. `AuthenticateChannel`
4. `EnforceContextBinding`
5. `InjectAuditContext`

Key distinction:
- `AuthenticateChannel` decides identity according to channel policy (`jwt`, `api_key`, `anonymous`, `jwt_or_anonymous`).
- `EnforceContextBinding` validates consistency (audience/tenant) and should not be treated as a login requirement.
- `RequireAuthenticatedContext` (`app.auth.required`) is the explicit route-level switch for requiring credentials on optional-auth channels.

## Aliases

| Alias | Class | Purpose |
| --- | --- | --- |
| `app.context` | `ResolveAppContext` | Resolve the channel and initial context. |
| `app.throttle` | `RateLimitByContext` | Apply context-aware rate limits. |
| `app.auth` | `AuthenticateChannel` | Authenticate per channel. |
| `app.binding` | `EnforceContextBinding` | Enforce audience and tenant binding. |
| `app.audit` | `InjectAuditContext` | Inject context into logs. |
| `app.scope` | `RequireScope` | Require at least one scope/capability. |
| `app.auth.required` | `RequireAuthenticatedContext` | Require authenticated context (`any`, `jwt`, or `api_key`). |
| `app.requires` | `RequireAbility` | Require any of the provided abilities. |
| `app.requires.all` | `RequireAllAbilities` | Require all provided abilities. |

## Evidence
- File: src/AppContextServiceProvider.php
  - Symbol: AppContextServiceProvider::registerMiddleware()
  - Notes: Registers aliases and the `app-context` middleware group.
- File: src/Middleware/RequireScope.php
  - Symbol: RequireScope::handle()
  - Notes: Enforces scope/capability checks.
- File: src/Middleware/RequireAuthenticatedContext.php
  - Symbol: RequireAuthenticatedContext::handle()
  - Notes: Enforces authenticated context per route/group.
- File: src/Middleware/RequireAllAbilities.php
  - Symbol: RequireAllAbilities::handle()
  - Notes: Enforces ALL abilities for a request.
