# Middleware Reference

## Aliases registrados
| Alias | Clase | Propósito |
| --- | --- | --- |
| `app.context` | ResolveAppContext | Resuelve canal y crea AppContext. |
| `app.auth` | AuthenticateChannel | Autenticación según canal. |
| `app.binding` | EnforceContextBinding | Binding de audience/tenant. |
| `app.scope` | RequireScope | Legacy scopes/capabilities. |
| `app.requires` | RequireAbility | OR lógico. |
| `app.requires.all` | RequireAllAbilities | AND lógico. |
| `app.throttle` | RateLimitByContext | Rate limiting por contexto. |
| `app.audit` | InjectAuditContext | Inyección de contexto en logs. |

## Middleware group `app-context`
Orden recomendado:
1) ResolveAppContext
2) RateLimitByContext
3) AuthenticateChannel
4) EnforceContextBinding
5) InjectAuditContext

## Nota sobre RequireAllScopes
Existe la clase `RequireAllScopes`, pero no está registrada como alias en el provider. Si la necesitas, debes registrarla manualmente en tu app.

## Evidence
- File: src/AppContextServiceProvider.php
  - Symbol: AppContextServiceProvider::registerMiddleware()
  - Notes: aliases y group `app-context`.
- File: src/Middleware/RequireAllScopes.php
  - Symbol: RequireAllScopes
  - Notes: clase existente no registrada por defecto.
