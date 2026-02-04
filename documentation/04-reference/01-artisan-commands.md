# Artisan commands

## `route:channel`

Lists routes for a given channel prefix or returns routes that do not belong to any channel.

**Signature**
```
php artisan route:channel {channel} {--orphans} {--json}
```

**Arguments**
- `channel`: `admin`, `site`, `mobile`, or `partner`.

**Options**
- `--orphans`: Show routes that do not belong to any channel.
- `--json`: Output as JSON.

**Examples**
```bash
php artisan route:channel admin
php artisan route:channel mobile --json
php artisan route:channel admin --orphans
```

## Evidence
- File: src/Commands/RoutesByChannel.php
  - Symbol: RoutesByChannel::$signature, RoutesByChannel::handle()
  - Notes: Defines and implements the `route:channel` command.
