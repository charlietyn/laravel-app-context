# Context-Aware Resources

## Overview
`ContextAwareResource` es una base para `JsonResource` que **adapta campos** según el canal (`admin`, `mobile`, `site`, `partner`).

## When to use / When NOT to use
**Úsalo cuando:**
- Quieres respuestas diferentes por canal sin duplicar recursos.

**Evítalo cuando:**
- Todos los canales deben ver exactamente el mismo shape.

## How it works
- `toArray()` revisa `app_context` del request.
- Llama a `toAdminArray`, `toMobileArray`, etc.
- Provee helpers para scopes/capabilities y channel checks.

## Configuration
No requiere config; depende de `AppContext` resuelto en el request.

## Usage examples
```php
use Ronu\AppContext\Resources\ContextAwareResource;

class UserResource extends ContextAwareResource
{
    protected function toPublicArray(Request $request): array
    {
        return ['id' => $this->id, 'name' => $this->name];
    }

    protected function toFullArray(Request $request): array
    {
        return [...$this->toPublicArray($request), 'email' => $this->email];
    }
}
```

## Edge cases / pitfalls
- Si no hay `AppContext`, cae a `toPublicArray()`.
- Para admin, `toAdminArray()` llama a `toFullArray()` por defecto.

## Evidence
- File: src/Resources/ContextAwareResource.php
  - Symbol: ContextAwareResource::toArray(), ContextAwareResource::whenHasScope()
  - Notes: selección por canal y helpers.

## Related docs
- [Feature: Authorization](authorization-abilities.md)
- [Architecture](../03-architecture.md)
