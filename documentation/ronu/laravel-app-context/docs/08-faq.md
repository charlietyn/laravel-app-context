# FAQ

### ¿Cómo obtengo el AppContext actual?
Puedes usar la Facade `AppContext` o el trait `HasAppContext` en controllers.

### ¿Qué middleware debo usar primero?
`app.context` debe correr antes de `app.auth`, `app.binding` y `app.audit`.

### ¿Cómo habilito auth opcional?
Configura el canal con `auth_mode=jwt_or_anonymous` y define `public_scopes`.

### ¿El paquete incluye rutas propias?
No. Debes definir las rutas de tu aplicación e incluir el middleware correspondiente.

## Evidence
- File: src/Facades/AppContext.php
  - Symbol: AppContext::current(), AppContext::isResolved()
  - Notes: acceso al contexto actual.
- File: src/Traits/HasAppContext.php
  - Symbol: HasAppContext::context()
  - Notes: helpers para controllers.
- File: src/AppContextServiceProvider.php
  - Symbol: AppContextServiceProvider::registerMiddleware()
  - Notes: alias y group de middleware.
- File: src/Auth/Authenticators/JwtAuthenticator.php
  - Symbol: JwtAuthenticator::tryAuthenticate()
  - Notes: auth opcional con `jwt_or_anonymous`.
