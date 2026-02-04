# 00-summary

## Resumen ejecutivo
Se revisó el paquete **laravel-app-context** (modo *package*) con foco en variables de entorno, claves de configuración y defaults de seguridad. Se identificaron variables declaradas sin uso directo en el paquete, una variable usada que no está documentada en los docs/.env, y varias claves de configuración declaradas sin lectura en el runtime del paquete (posibles remanentes o hooks para consumidores). También se detectó una inconsistencia de unidades para TTL de JWT entre `.env.example` y `config/app-context.php`.

## Métricas
- ENV declaradas (docs + .env.example): **53**
- ENV usadas en runtime (via `env()` en config): **51**
- ENV declaradas pero no usadas por el paquete: **3**
- ENV usadas pero no documentadas: **1**
- Posibles typos/mismatch de unidades: **1** (TTL JWT)
- Config keys declaradas sin lectura en runtime del paquete: **3**

## Riesgos y recomendaciones
- **JWT dev fallback habilitado por defecto**: riesgo de degradar a HS256 en producción si faltan claves RSA. Recomendar desactivar por defecto en entornos no dev y documentar claramente la condición de activación.
- **TTL JWT con unidades inconsistentes**: `.env.example` usa minutos, mientras la configuración del paquete espera segundos. Ajustar documentación y valores de ejemplo.
- **Claves de configuración sin uso directo**: `security.strict_algorithm_check`, `security.anomaly_detection.*`, `jwt.blacklist_grace_period` no aparecen en el runtime del paquete. Marcar como “needs manual confirm” antes de eliminar.

