# Artisan Commands

## route:channel
Lista rutas por canal (admin/site/mobile/partner) o rutas huérfanas.

```bash
php artisan route:channel admin
php artisan route:channel mobile --json
php artisan route:channel --orphans
```

### Parámetros
- `channel`: `admin|site|mobile|partner`
- `--orphans`: rutas que no pertenecen a ningún canal
- `--json`: salida JSON

## Evidence
- File: src/Commands/RoutesByChannel.php
  - Symbol: RoutesByChannel::handle(), RoutesByChannel::$signature
  - Notes: definición del comando y opciones.
