# Testing

## Enfoque de tests
Hay tests unitarios para `AppContext`, `ContextResolver`, middleware y repositorios. Se ejecutan con PHPUnit vía `composer test`.

## Comandos
```bash
composer test
composer test-coverage
```

## Evidence
- File: composer.json
  - Symbol: scripts.test, scripts.test-coverage
  - Notes: comandos oficiales de test.
- File: tests/Unit/AppContextTest.php
  - Symbol: AppContextTest
  - Notes: ejemplos de tests unitarios.
- File: tests/Unit/ContextResolverTest.php
  - Symbol: ContextResolverTest
  - Notes: cobertura de resolución de canal.
