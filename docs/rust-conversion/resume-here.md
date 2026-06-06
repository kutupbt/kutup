# Resume here

**State:** crypto ✅, CLI ✅ (16 commands), server 🟡 — slices 1 & 2 done. Branch
`claude/go-rust-rewrite-G16zO`; `cargo build`/`test`/`clippy` green.

Done in the server crate:
- **Slice 1** (skeleton): `error.rs` (AppError → IntoResponse, `{"error":…}`),
  `models.rs` (full DTO mirror of `handlers/models.go`), `openapi.rs` (utoipa ApiDoc;
  spec at `/api-docs/openapi.json` — interactive swagger-ui deferred, see roadmap),
  panic/tracing/body-limit/CORS layers, real `/api/health` body.
- **Slice 2** (auth+middleware): `jwt.rs`, `totp.rs`, `ssrf.rs`, `ratelimit.rs`,
  `middleware.rs` (AuthUser/AdminUser extractors), `handlers/auth.rs` (all `/auth/*`,
  `/user/*`, `/users/by-email/:email`), `bootstrap_admins`. Verified live against
  Postgres (register→login→me→refresh→2FA→rate-limit).

## Next action — Phase 3 slice 3 (storage + files) in `kutup-server`

1. Read `backend/services/storage.go`, `backend/services/quota*.go`,
   `backend/handlers/{collections,files,file_versions,file_assets,devices}.go`.
2. Add dep: `aws-sdk-s3` (+ `aws-config`/`aws-credential-types` as needed).
3. Implement the storage service (S3 client mirroring `NewStorage`), quota helpers, and
   the collections/files/versions/assets/devices handlers; register routes in
   `build_router`. Use the `AuthUser` extractor for auth.
4. Gate: `cargo clippy --all-targets -- -D warnings` + tests; live test against the
   SeaweedFS S3 from `docker compose` (a test Postgres is already used for slice 2).

Local test infra: `docker run … postgres:16-alpine` on `127.0.0.1:5433`
(db/user `kutup`, pw `kutup_dev_password`); run the server with dummy `S3_*` until the
storage slice needs real SeaweedFS.

See [`server/plan.md`](server/plan.md) for the full 8-slice build order and
[`server/routes.md`](server/routes.md) for the endpoint inventory + sqlx notes.

## Milestones

- **Before declaring the CLI done:** run `scripts/verify-cli.sh` on a VM with a live
  stack — full guide in [`cli/testing.md`](cli/testing.md) (build, test account, manual
  walkthrough, differential testing vs the Go CLI, known quirks, troubleshooting).
- **After all server slices:** regenerate the OpenAPI spec (utoipa) and diff it against
  `backend/docs/swagger.yaml`; port the Go test suites; then remove `backend/` +
  `cmd/kutup/`.

## Golden rules

- Mirror wire formats **exactly** (see [`approach.md`](approach.md)).
- Keep the three crypto mirrors in sync and **regenerate vectors** on any crypto change
  (see [`crypto/README.md`](crypto/README.md)).
- clippy-clean + rustfmt + tests on **every** commit.
- No silent stubs — defer to `docs/roadmap.md` instead.
