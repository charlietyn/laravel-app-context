# Introduction

Laravel App Context is a Laravel package for **multi-channel application context management**. It lets you define channels (mobile, admin, site, partner), resolve an `AppContext` per request, authenticate per channel (JWT, API key, or anonymous), and apply channel-specific authorization, rate limiting, and audit logging.

This package is designed for applications that expose multiple surfaces (mobile apps, admin dashboards, partner APIs) and need consistent authentication, authorization, and audit behavior across those surfaces.

**Next:** [Concepts](01-concepts.md)

[Back to index](../index.md)
