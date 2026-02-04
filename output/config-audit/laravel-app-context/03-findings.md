# 03-findings

## High

### 1) JWT dev fallback habilitado por defecto
- **Evidence**
  - File: config/app-context.php
  - Symbol: app-context.jwt.dev_fallback.enabled
  - Snippet:
    ```php
    'dev_fallback' => [
        'enabled' => env('JWT_DEV_FALLBACK', true),
    ```
  - Reason: El fallback simétrico se activa por defecto si faltan claves RSA.
- **Evidence**
  - File: src/AppContextServiceProvider.php
  - Symbol: AppContextServiceProvider::configureJwtFallback
  - Snippet:
    ```php
    if (! ($fallbackConfig['enabled'] ?? true)) {
        return;
    }
    ```
  - Reason: La ejecución del fallback depende solo de `enabled` y del entorno.
- **Impacto**: En entornos no-dev mal configurados (claves RSA ausentes), se puede degradar a HS256, lo cual reduce garantías de seguridad.
- **Proposed fix**: Documentar explícitamente en docs y `.env.example` que **JWT_DEV_FALLBACK debe ser false** fuera de entornos dev. Considerar cambiar el default a `false` o atarlo a `app.env`.

## Medium

### 2) Inconsistencia de unidades en JWT_TTL / JWT_REFRESH_TTL
- **Evidence**
  - File: .env.example
  - Symbol: JWT_TTL / JWT_REFRESH_TTL
  - Snippet:
    ```bash
    # Token TTL in minutes (60 = 1 hour)
    JWT_TTL=60

    # Refresh token TTL in minutes (20160 = 14 days)
    JWT_REFRESH_TTL=20160
    ```
  - Reason: El ejemplo declara minutos.
- **Evidence**
  - File: config/app-context.php
  - Symbol: app-context.jwt.ttl / refresh_ttl
  - Snippet:
    ```php
    // Token TTL in seconds
    'ttl' => env('JWT_TTL', 3600), // 1 hour

    // Refresh token TTL in seconds
    'refresh_ttl' => env('JWT_REFRESH_TTL', 1209600), // 14 days
    ```
  - Reason: La configuración espera **segundos**.
- **Impacto**: TTL podría ser 60s en vez de 1h si se siguen los ejemplos; expiración inesperada.
- **Proposed fix**: Ajustar `.env.example` para usar segundos (3600 / 1209600) o cambiar comentarios para aclarar unidades.

### 3) APP_URL usado como fallback, no documentado
- **Evidence**
  - File: config/app-context.php
  - Symbol: app-context.jwt.issuer
  - Snippet:
    ```php
    'issuer' => env('JWT_ISSUER', env('APP_URL', 'http://localhost')),
    ```
  - Reason: APP_URL afecta issuer JWT pero no aparece en docs/.env.example.
- **Impacto**: Configuración incompleta en ambientes nuevos; issuer podría resolverse con defaults inesperados.
- **Proposed fix**: Documentar APP_URL en sección de variables y `.env.example` como fallback del issuer.

### 4) Variables declaradas sin uso directo en el paquete
- **Evidence**
  - File: .env.example
  - Symbol: APP_DEV / JWT_SECRET
  - Snippet:
    ```bash
    APP_DEV=local
    JWT_SECRET=your-super-secret-key-min-32-characters
    ```
  - Reason: No existen `env()` o `config()` del paquete que consuman estas variables.
- **Impacto**: Ruido de configuración y confusión para usuarios del paquete.
- **Proposed fix**: Marcar como “optional/legacy” en docs o remover del `.env.example` tras confirmación manual (JWT_SECRET suele ser de jwt-auth).

## Low

### 5) Config keys declaradas sin lectura en runtime del paquete
- **Evidence**
  - File: config/app-context.php
  - Symbol: app-context.jwt.blacklist_grace_period
  - Snippet:
    ```php
    'blacklist_grace_period' => 30,
    ```
  - Reason: No hay callsites en `src/` (búsqueda literal sin resultados).

- **Evidence**
  - File: config/app-context.php
  - Symbol: app-context.security.strict_algorithm_check
  - Snippet:
    ```php
    'strict_algorithm_check' => true,
    ```
  - Reason: No hay callsites en `src/`.

- **Evidence**
  - File: config/app-context.php
  - Symbol: app-context.security.anomaly_detection.*
  - Snippet:
    ```php
    'anomaly_detection' => [
        'enabled' => env('APP_CONTEXT_ANOMALY_DETECTION', false),
    ```
  - Reason: No hay callsites en `src/`.

- **Impacto**: Posible deuda de configuración o flags sin efecto.
- **Proposed fix**: Marcar como **Needs manual confirm**. Si no hay uso real, remover y documentar en release notes.

## Needs manual confirm
- JWT_SECRET puede ser necesario para `php-open-source-saver/jwt-auth` aunque el paquete no lo lea.
- Variables de `client_repository` faltantes en `.env.example` pueden ser intencionales si se usan solo en escenarios avanzados.

