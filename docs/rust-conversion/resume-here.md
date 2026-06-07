# Resume here

**State:** crypto ✅, CLI ✅ (16 commands), server 🟡 — slices 1–5 done. Branch
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
- **Slice 3** (storage+data): `storage.rs` (aws-sdk-s3) + `handlers/{collections,files,
  file_versions,file_assets,devices}.rs` + shared access helpers. Live-verified vs
  Postgres + SeaweedFS (upload/download/version/asset SHA round-trips, quota, cascade
  delete). Deferred to slice 6: collections share-federated + fed-pubkey (need SSRF +
  outbound HTTP).
- **Slice 4** (tus.io): `handlers/tus.rs` (OPTIONS/POST/HEAD/PATCH/DELETE) + S3 multipart
  in `storage.rs` (`CompletedPart`, create/upload_part/complete/abort). Soft-quota
  reservation via the `uploads` table; final PATCH finalises → `files` row + atomic
  `storage_used_bytes` + `X-Kutup-File-Id`. A `tus_options_passthrough` outermost layer
  serves non-preflight OPTIONS discovery (tower-http CorsLayer swallows all OPTIONS;
  Fiber passes non-preflight ones through). Live-verified vs Postgres + SeaweedFS (6 MiB
  two-part round-trip SHA match, error paths, abort, exact quota commit).
- **Slice 5** (collab WS): `hub.rs` (in-memory per-fileId rooms; mpsc writer task +
  Notify-based close; 2 s backpressure) + `handlers/collab.rs` (`ws()` PreUpgrade auth →
  `WebSocketUpgrade::on_upgrade`; hello/peers control msgs, Ed25519 frame verify via
  `kutup-crypto::envelope`, durable→`file_update_log` / ephemeral→broadcast-only, resume
  replay). devices.rs revoke wired to `hub.close_device`. Route
  `/api/files/:fileId/collab/ws`. axum `ws` feature + `futures-util` added. Live-verified
  (raw-socket WS + real Ed25519 frames): two-peer join/hello/peer-list, durable+ephemeral
  relay, bad-sig/wrong-sender drop, resume replay, revoke tears down the WS.

## Next action — Phase 3 slice 6 (sharing + federation) in `kutup-server`

1. Read `backend/handlers/{shares,federation,fedproxy}.go` + `backend/utils/ssrf.go`
   (the Rust `ssrf.rs` guard already exists from slice 2).
2. Implement `/share/*`, `/fed/*`, `/fed-proxy/*` and the deferred collections
   `share-federated` + `/collections/fed-pubkey` (slice 3 deferral) — all outbound
   federation calls go through the SSRF guard + an HTTP client (add `reqwest` to the
   server crate). `PresignedDownload` + `CopyObject` land in `storage.rs` here (presign is
   used by `shares.go`).
3. Gate: `cargo clippy --all-targets -- -D warnings` + tests; live test against the test
   Postgres + SeaweedFS (presigned download round-trip; a loopback federation pair if
   feasible).

Local test infra: `kutup-test-pg` (127.0.0.1:5433, db/user `kutup`, pw
`kutup_dev_password`) + `kutup-test-s3` SeaweedFS (127.0.0.1:8333, creds
kutupkey/kutupsecret, bucket `kutup-files` with object-lock/versioning; s3 config at
`~/kutup-test/swfs/s3.json`). Run the server with the `DATABASE_URL`/`JWT_SECRET`/`S3_*`
env vars (see git history of this doc / the slice-4 test commands).

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
