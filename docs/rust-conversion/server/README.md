# kutup-server (Phase 3 🟡 scaffold)

Rust rewrite of `backend/` (Go/Fiber, ~10.9k LOC prod + 3.3k tests). Binary
`kutup-server`, listens on `:3000`. Axum + sqlx.

## Done (the scaffold)

- `src/config.rs` — env loader mirroring `backend/config/config.go` (same vars + defaults,
  and the `JWT_SECRET` ≥ 32-char guard).
- `src/db.rs` — sqlx `PgPool` connect + ping, and migrations run via
  `sqlx::migrate!("../../backend/db/migrations")`. Those files are `NNN_name.up.sql` /
  `.down.sql` (sqlx's reversible format), so the existing 18 migrations are consumed
  **unchanged** and validated at compile time. The schema is the E2EE contract — not
  modified.
- `src/main.rs` — the Axum app: startup sequence (connect → migrate → serve),
  `/api/health`, an env-driven CORS allowlist (explicit origins + credentials, never
  wildcard; includes the tus headers), and `AppState { pool, config }`.

## Next

- Build order: [`plan.md`](plan.md) (8 slices).
- Endpoint inventory + sqlx/migration gotchas: [`routes.md`](routes.md).
- The immediate next slice (auth + middleware) is detailed in
  [`../resume-here.md`](../resume-here.md).
