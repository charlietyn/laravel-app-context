# Security

Laravel App Context includes multiple security layers:

## JWT hardening
- Algorithm whitelist prevents `none` algorithm confusion.
- Issuer and audience validation.
- Token blacklist with cache store support.

## API key protections
- Hash verification (bcrypt/argon2id).
- Expiration and revocation checks.
- IP allowlist enforcement (CIDR support).

## Tenant binding
- Enforces tenant binding when `tenant_mode` is `multi` and tenant enforcement is enabled.

## Audit logging
- Injects context into logs and redacts sensitive headers.

## Development fallback
- In configured development environments, missing RSA keys can fall back to a symmetric algorithm to avoid blocking local development.

[Back to index](../index.md)
