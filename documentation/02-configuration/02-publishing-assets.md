# Publishing assets

Laravel App Context ships with a single publishable asset: its configuration file.

## Publish config

```bash
php artisan vendor:publish --tag=app-context-config
```

This will create `config/app-context.php`.

## Migrations, views, translations

This package does not ship with migrations, views, or translations. If you use the Eloquent client repository, you must create and manage the client tables in your application.

[Back to index](../index.md)
