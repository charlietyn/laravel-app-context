# Middleware

The service provider registers the following aliases and middleware group:

## Middleware group

| Group | Pipeline |
| --- | --- |
| `app-context` | `ResolveAppContext` → `RateLimitByContext` → `AuthenticateChannel` → `EnforceContextBinding` → `InjectAuditContext` |

## Aliases

| Alias | Class | Purpose |
| --- | --- | --- |
| `app.context` | `ResolveAppContext` | Resolve the channel and initial context. |
| `app.throttle` | `RateLimitByContext` | Apply context-aware rate limits. |
| `app.auth` | `AuthenticateChannel` | Authenticate per channel. |
| `app.binding` | `EnforceContextBinding` | Enforce audience and tenant binding. |
| `app.audit` | `InjectAuditContext` | Inject context into logs. |
| `app.scope` | `RequireScope` | Require at least one scope/capability. |
| `app.requires` | `RequireAbility` | Require any of the provided abilities. |
| `app.requires.all` | `RequireAllAbilities` | Require all provided abilities. |

## Evidence
- File: src/AppContextServiceProvider.php
  - Symbol: AppContextServiceProvider::registerMiddleware()
  - Notes: Registers aliases and the `app-context` middleware group.
- File: src/Middleware/RequireScope.php
  - Symbol: RequireScope::handle()
  - Notes: Enforces scope/capability checks.
- File: src/Middleware/RequireAllAbilities.php
  - Symbol: RequireAllAbilities::handle()
  - Notes: Enforces ALL abilities for a request.
