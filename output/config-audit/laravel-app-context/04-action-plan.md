# 04-action-plan

## Plan por etapas

### PR1 — Docs y .env.example (Quick wins)
- Documentar APP_URL como fallback del issuer JWT.
- Alinear unidades de JWT_TTL/JWT_REFRESH_TTL (segundos) en `.env.example` y docs.
- Añadir variables faltantes relacionadas a `client_repository` y `jwt.dev_fallback` en `.env.example`.
- Marcar APP_DEV y JWT_SECRET como **legacy/optional** si se decide conservar.

### PR2 — Config cleanup (Medium risk)
- Confirmar uso real de:
  - `app-context.jwt.blacklist_grace_period`
  - `app-context.security.strict_algorithm_check`
  - `app-context.security.anomaly_detection.*`
- Si no hay uso real, remover del config y documentar en release notes.

### PR3 — Code cleanup (High risk / optional)
- Si se elimina `jwt.blacklist_grace_period` o `security.anomaly_detection`, actualizar cualquier integración externa.
- Validar en apps consumidoras que no dependan de esos flags.

## Checklist de verificación
- `composer test`
- `vendor/bin/phpunit`
- Prueba manual en aplicación consumidora (si existe):
  - JWT RS256 sin claves -> confirmar comportamiento de fallback
  - TTL y refresh TTL esperados
  - Rate limiting por canal

## Estrategia de rollback
- Mantener release notes con los keys eliminados.
- Reintroducir rápidamente keys removidos si se detecta dependencia en downstream.
- Publicar versión patch con compatibilidad retroactiva si hay impactos.

