# Installation

## 1) Instalar vía Composer
```bash
composer require ronu/laravel-app-context
```

## 2) Publicar configuración
```bash
php artisan vendor:publish --tag=app-context-config
```
Esto crea `config/app-context.php` con los defaults del paquete.

## 3) Auto-discovery del Service Provider
El provider se registra automáticamente por `extra.laravel.providers`. Si tu proyecto desactiva auto-discovery, agrega manualmente:
```php
// config/app.php
'providers' => [
    Ronu\AppContext\AppContextServiceProvider::class,
],
```

## 4) (Opcional) Guard `app-context`
El package registra un guard personalizado llamado `app-context`. Úsalo si necesitas integrarlo con el sistema de guards de Laravel.

## Evidence
- File: composer.json
  - Symbol: extra.laravel.providers
  - Notes: auto-discovery del provider.
- File: src/AppContextServiceProvider.php
  - Symbol: AppContextServiceProvider::boot(), AppContextServiceProvider::registerAuthGuard()
  - Notes: publicación de config y registro del guard.
- File: config/app-context.php
  - Symbol: (archivo completo)
  - Notes: config publicada por el tag `app-context-config`.
