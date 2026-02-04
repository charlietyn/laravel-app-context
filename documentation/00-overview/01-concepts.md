# Concepts

## AppContext
`AppContext` is an immutable value object describing the current request's channel, authentication state, tenant, scopes, capabilities, and metadata. It is resolved by middleware and stored in the request attributes and container.

## Channels
Channels define how a request is classified (e.g., `mobile`, `admin`, `site`, `partner`). Each channel configures:
- How it is detected (subdomain/path)
- Authentication mode (`jwt`, `api_key`, `anonymous`, `jwt_or_anonymous`)
- Scopes/capabilities and authorization rules
- Rate limit profile
- Tenant mode

## Detection strategies
Channel detection is driven by `detection_strategy` and optionally `auto_detection_rules`:
- `auto` (default): choose path/subdomain based on host patterns
- `path`: resolve by URL prefix
- `subdomain`: resolve by subdomain
- `strict`: both path and subdomain must match the same channel

## Authentication modes
- **JWT**: validates JWTs, verifies issuer/audience, and builds scopes.
- **API key**: validates API keys, optional IP allowlist enforcement, and builds capabilities.
- **Anonymous**: builds a public context for open access.
- **jwt_or_anonymous**: attempts JWT auth, but falls back to anonymous access when configured.

## Authorization
Authorization uses scopes (JWT) and capabilities (API key). Middleware is provided to enforce required abilities on routes.

[Back to index](../index.md)
