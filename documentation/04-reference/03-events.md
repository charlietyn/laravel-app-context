# Events

This package does **not** define any custom events or listeners. All behavior is driven by middleware, authenticators, and verifiers.

If you need events, you can emit your own at the application layer (e.g., after context resolution or authentication) using Laravel's event system.

## Evidence
- File: src/AppContextServiceProvider.php
  - Symbol: AppContextServiceProvider::register()
  - Notes: Registers config, bindings, middleware, and commands without event/listener registration.
