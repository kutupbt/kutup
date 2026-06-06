# Phase 3 build order

Each slice = one commit. Gate per slice = compiles + `cargo clippy -p kutup-server
--all-targets -- -D warnings` + DB-less unit tests where possible.

1. **Skeleton polish** — `AppState`, an error type (`thiserror` → `IntoResponse`),
   models/DTOs (`backend/models/*.go`, `backend/handlers/models.go`), tracing, a
   panic/recover layer, the utoipa `ApiDoc` + swagger-ui, 10 GB body limit + streamed
   request body.
2. **Auth + middleware** — `backend/utils/jwt.go` → `jsonwebtoken` (identical claims +
   lifetimes: access 15m / refresh 7d / setup 15m / pre-auth 5m),
   `backend/middleware/{auth,admin,ratelimit}.go`, `backend/handlers/auth.go`
   (settings / register / login[/preflight, /2fa] / recover[/preflight] / refresh /
   complete-setup), `backend/services/totp.go`, `bcrypt`, reuse `backend/utils/ssrf.go`.
3. **Storage + files** — `backend/services/storage.go` → `aws-sdk-s3`,
   `backend/services/quota*.go`,
   `backend/handlers/{collections,files,file_versions,file_assets}.go`.
4. **tus.io** — `backend/handlers/tus.go` (OPTIONS / POST / HEAD / PATCH / DELETE), S3
   multipart (≥ 5 MiB parts), soft quota reservation via the `uploads` table, finalize →
   `files` row + atomic `storage_used_bytes`, `X-Kutup-File-Id` on the final PATCH.
5. **Collab WS** — `backend/handlers/{collab,collab_hub}.go` → Axum WS + an in-memory hub
   (tokio broadcast/mpsc per `fileId` room), `envelope::verify` via `kutup-crypto`, a
   256-frame backpressure buffer with a 2 s timeout, persist frames to `file_update_log`.
6. **Sharing + federation** — `backend/handlers/{shares,federation,fedproxy}.go` (+ the
   SSRF guard).
7. **Admin + background jobs + sweep CLI** — `backend/handlers/admin.go`,
   `backend/services/{version_cleanup,quota_reconcile,uploads_sweeper,orphan_sweep}.go`,
   the `backend/cmd/sweep.go` subcommand.
8. **Verification** — re-implement the 21 Go `*_test.go` suites against a per-test
   Postgres schema (port `backend/internal/testdb`); run the existing frontend Playwright
   flows + the Rust CLI against the Rust server; regenerate the OpenAPI spec via utoipa and
   diff the endpoint set against `backend/docs/swagger.yaml` (43 routes + 1 WS).

## Go → Rust mapping

| Go | Rust |
|---|---|
| Fiber | Axum |
| `gofiber/contrib/websocket` | `axum::extract::ws` |
| `jackc/pgx` | `sqlx` |
| `golang-migrate` | `sqlx::migrate!` |
| `aws-sdk-go-v2` | `aws-sdk-s3` |
| `golang-jwt` | `jsonwebtoken` |
| `pquerna/otp` | `totp-rs` |
| `golang.org/x/crypto/bcrypt` | `bcrypt` |
| `google/uuid` | `uuid` |
| `swaggo/swag` | `utoipa` (+ `utoipa-swagger-ui`) |
| `crypto/ed25519` (envelope verify) | `kutup-crypto::envelope` |
