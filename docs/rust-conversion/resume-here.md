# Resume here

**State:** crypto ✅, CLI ✅ (16 commands), server 🟡 scaffold. Branch
`claude/go-rust-rewrite-G16zO`; `cargo build` is green.

## Next action — Phase 3 slice 2 (auth + middleware) in `kutup-server`

1. Read `backend/utils/jwt.go`, `backend/middleware/{auth,admin,ratelimit}.go`,
   `backend/handlers/auth.go`, `backend/services/totp.go`, `backend/handlers/models.go`.
2. Add deps: `jsonwebtoken`, `bcrypt`, `totp-rs` (later `aws-sdk-s3`, `utoipa`).
3. Implement:
   - a server error type (`thiserror` + `axum::response::IntoResponse`);
   - JWT issue/verify with **identical** claims + lifetimes (access 15m / refresh 7d /
     setup 15m / pre-auth 5m);
   - an auth extractor + the rate-limit middleware;
   - the `/auth/*` + `/user/me` handlers;
   - register the route group in `build_router` (`crates/kutup-server/src/main.rs`).
4. Gate: `cargo clippy -p kutup-server --all-targets -- -D warnings`; DB-less unit tests
   for JWT + SSRF + TOTP. Commit.

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
