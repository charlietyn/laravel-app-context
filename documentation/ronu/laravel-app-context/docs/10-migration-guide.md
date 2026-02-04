# Migration Guide

Este repositorio incluye un `docs/MIGRATION.md` con pasos detallados para migrar desde Auth nativo, Sanctum, Passport o JWT custom. Esta guía resume lo esencial y apunta al archivo oficial.

## Pasos mínimos recomendados
1) Instalar paquete y publicar config.
2) Definir canales y `auth_mode` correctos.
3) Ajustar middleware en rutas (`app-context`).
4) Emitir JWT con `aud`, `scp`, `tid` según canal/tenant.
5) Migrar repositorio de clients si pasas de `config` a `eloquent`.

## Dónde ampliar
Consulta `docs/MIGRATION.md` para pasos por tipo de migración.

## Evidence
- File: docs/MIGRATION.md
  - Symbol: (archivo completo)
  - Notes: guía detallada de migración incluida en el repo.
- File: src/AppContextServiceProvider.php
  - Symbol: AppContextServiceProvider::registerMiddleware()
  - Notes: middleware group recomendado para rutas.
- File: config/app-context.php
  - Symbol: channels, client_repository
  - Notes: configuración que suele ajustarse en migraciones.
