# FAQ

## Does the package ship with database migrations?
No. If you use the Eloquent client repository, you must provide your own schema.

## Can I use config-based clients in production?
Yes, for low-volume integrations. For large or dynamic client lists, use the Eloquent repository or a custom repository.

## Do I have to use all middleware?
No. You can use individual middleware aliases, but the `app-context` group provides the recommended pipeline.

## Does this package manage JWT issuing?
No. It validates JWTs via `php-open-source-saver/jwt-auth`. Token issuing remains your responsibility.

## In `jwt_or_anonymous`, why do I get 403 (missing permission) instead of 401 (unauthenticated)?
Because optional-auth channels may resolve to anonymous context when no token is present. If your route has `app.scope:*`, authorization fails after auth step and you get 403. Use `app.auth.required:jwt` when a specific route must force authentication.

## If `app.auth` is already in my group, why do I still need a protected subgroup?
`app.auth` authenticates according to channel policy. In `jwt_or_anonymous`, that policy explicitly allows anonymous fallback in many cases. A protected subgroup is where you declare stricter route-level policy, for example `app.auth.required:jwt` for checkout/orders.

## Should `JWT required` logic live in the package or each project?
If this is a cross-project concern, keep it in the package (as `app.auth.required`). If it is one-off business logic, implement it in the consumer app. For most teams, package-level + route-level config is the best long-term reuse strategy.

## What is the practical difference between `app.auth`, `app.binding`, and `app.auth.required`?
- `app.auth`: resolves identity (JWT/API key/anonymous) according to channel auth mode.
- `app.binding`: validates context binding constraints (audience, tenant), not login requirement.
- `app.auth.required`: enforces that an authenticated identity is present on this route/group (`any`, `jwt`, `api_key`).

[Back to index](../index.md)
