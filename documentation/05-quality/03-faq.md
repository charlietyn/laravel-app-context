# FAQ

## Does the package ship with database migrations?
No. If you use the Eloquent client repository, you must provide your own schema.

## Can I use config-based clients in production?
Yes, for low-volume integrations. For large or dynamic client lists, use the Eloquent repository or a custom repository.

## Do I have to use all middleware?
No. You can use individual middleware aliases, but the `app-context` group provides the recommended pipeline.

## Does this package manage JWT issuing?
No. It validates JWTs via `php-open-source-saver/jwt-auth`. Token issuing remains your responsibility.

[Back to index](../index.md)
