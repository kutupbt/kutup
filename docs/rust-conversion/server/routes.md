# Route inventory + sqlx notes

> Historical Go-to-Rust conversion inventory. It is not the current route
> contract; use [`../../api.md`](../../api.md) and the generated OpenAPI document.
> In particular, the legacy Drive `/fed`, `/fed-proxy`, `share-federated`, and
> `fed-pubkey` routes listed below were removed by unified federation Phase D.

Register each group in `build_router` (`crates/kutup-server/src/main.rs`) as its handlers
land. `/api/health` is done. The full source of truth is `backend/main.go` (~lines
117–230).

## Pending route groups

- **`/auth/*`** — `settings`, `register`, `login`, `login/preflight`, `login/2fa`,
  `recover`, `recover/preflight`, `refresh`, `complete-setup`.
- **`/user/*`** — `me`, `2fa/setup`, `2fa/verify`, `2fa` (DELETE). Plus
  `/users/by-email/:email`.
- **`/collections/*`** — list, create, `:id` GET/PUT/DELETE, `:id/color`, `:id/share`,
  `:id/share-federated`, `fed-pubkey`, `:id/files`.
- **`/files/*`** — `upload`, `:id/download`, `:id` (DELETE / PUT metadata),
  `:id/versions` (+ `:vid/download`, PATCH), `:id/snapshot-blob`, `:id/assets/*`.
- **`/uploads/*`** — tus (OPTIONS / POST / HEAD / PATCH / DELETE).
- **`/files/:fileId/collab/ws`** — WebSocket.
- **`/fed/*`** — `users`, `invites/:token`, `shares/:token/files`
  (+ `/:fileId/download`, POST).
- **`/fed-proxy/*`** — `incoming` (GET / POST / DELETE `/:id`), `:shareId/files`
  (+ `/:fileId/download`), `:shareId/upload`.
- **`/admin/*`** — users (CRUD), `stats`, `settings` (GET / PUT).
- **`/devices/*`** — register, list, `:id` delete.
- **`/share/*`** — public create, `:token`, `:token/files`, `:token/download/:fileId`.

## sqlx / migrations

- Migration files are `NNN_name.up.sql` / `.down.sql` — sqlx's **reversible** format — so
  they're consumed directly from `backend/db/migrations/` (no copy, no schema change).
- sqlx tracks applied migrations in `_sqlx_migrations` (≠ golang-migrate's
  `schema_migrations`). On a DB already migrated by Go, sqlx will try to re-run everything
  → use a **fresh** DB for the Rust server, or one-time reconcile the tracking table.
  Pre-production, a fresh DB is fine.
- `query!` / `query_as!` macros need a live DB at compile time **or** a `cargo sqlx
  prepare` offline cache (`.sqlx/`). Plan: use the offline cache so CI builds without a DB;
  or use the runtime (unchecked) `sqlx::query` variants where a checked query is awkward.
- DB-less work (config, routing, crypto, framing) is unit-tested now; full integration
  needs Postgres + S3/SeaweedFS on the VM.
