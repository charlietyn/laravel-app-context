# Exceptions Reference

## AppContextException
Base para errores del paquete. Renderiza JSON con `error`, `message` y `context`.

## AuthenticationException (401)
Errores de credenciales: token inválido, API key faltante, blacklist, etc.

## AuthorizationException (403)
Errores de permisos: scopes/capabilities faltantes.

## ContextBindingException (403)
Errores de binding: audience, tenant o canal inválidos, o `deny_by_default`.

## Evidence
- File: src/Exceptions/AppContextException.php
  - Symbol: AppContextException::render()
  - Notes: formato JSON y status code.
- File: src/Exceptions/AuthenticationException.php
  - Symbol: AuthenticationException::*
  - Notes: errores 401 específicos.
- File: src/Exceptions/AuthorizationException.php
  - Symbol: AuthorizationException::*
  - Notes: errores 403 por permisos.
- File: src/Exceptions/ContextBindingException.php
  - Symbol: ContextBindingException::*
  - Notes: errores 403 de binding.
