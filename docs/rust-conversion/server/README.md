# `kutup-server` conversion record

**Status:** complete. `crates/kutup-server` is the only backend implementation;
the former Go/Fiber `backend/` tree was removed.

The Rust server is an Axum/sqlx application, listens on internal port `3000`,
embeds migrations from `crates/kutup-server/migrations/`, stores encrypted
objects through the S3 API, and exposes its generated OpenAPI document at
`GET /api-docs/openapi.json`.

Use these current references:

- [`../../api.md`](../../api.md) for the HTTP contract;
- [`../../architecture.md`](../../architecture.md) for system boundaries;
- [`../../contributing.md`](../../contributing.md) for build and test commands;
- [`../../self-hosting.md`](../../self-hosting.md) for deployment; and
- `crates/kutup-server/src/main.rs` plus generated OpenAPI for the exact route
  set.

[`plan.md`](plan.md) and [`routes.md`](routes.md) are historical Go-to-Rust
inventories. Their deleted Go paths and pre-federation route names must not be
used as current implementation guidance.
