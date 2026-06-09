# Resume here

**State: DONE ✅** — the Go→Rust rewrite is complete and the Go tree was removed (cutover).
Branch `claude/go-rust-rewrite-G16zO`; `cargo build`/`test`/`clippy`/`fmt` green.

- **crypto** ✅ (`kutup-crypto`; byte-parity vectors + a BIP39 `mnemonic` module).
- **CLI** ✅ (`kutup-cli`; all former Go commands **plus** a new `register`). Differentially
  verified: the old Go CLI and the Rust CLI drive the same account through the same battery
  against **both** servers identically (incl. cross-binary upload/download SHA).
- **server** ✅ (`kutup-server`; slices 1–8). Route set matches the old Go backend exactly
  (72 method+paths). Containerized (`Dockerfile.server`), wired into `docker-compose*.yml`.
- **cutover** ✅ — `backend/` + `cmd/kutup/` deleted; migrations moved to
  `crates/kutup-server/migrations/`; CI release builds the Rust CLI; docs updated.
- Deferrals (see `docs/roadmap.md`): per-path OpenAPI operations + interactive Swagger UI;
  `.excalidraw` asset extraction. Federation Go↔Rust cross-server test was intentionally
  skipped (SSRF blocks loopback/private IPs on one host; handlers are verified single-server).

Everything below is the historical slice-by-slice record.

---

**(historical) State:** crypto ✅, CLI ✅ (16 commands), server 🟡 — slices 1–7 done. Branch
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
- **Slice 6** (sharing + federation): `handlers/shares.rs` (`/share/*` public links),
  `handlers/federation.rs` (`/fed/*` remote-facing, token-auth), `handlers/fedproxy.rs`
  (`/fed-proxy/*` authed proxy, SSRF-checked at accept, FED_CLIENT no-redirect),
  collections `share_federated` + `fetch_remote_pubkey`, `storage.rs::presigned_download`.
  FED_CLIENT + `random_token` in handlers/mod.rs; reqwest `stream` feature + rand added.
  Live-verified vs Postgres + SeaweedFS (public share presigned-download SHA, expiry 410,
  non-owned 403; fed share/upload/download/delete + balanced quota; fed-proxy round-trip
  via self-loopback; SSRF loopback rejection 400). Go's `CopyObject` left unported (dead).
- **Slice 7** (admin + jobs): `handlers/admin.rs` (`/admin/*` users CRUD + stats + settings,
  behind the `AdminUser` extractor), `jobs.rs` (version_cleanup / quota_reconcile /
  uploads_sweeper as boot+interval background tasks via `jobs::spawn_all`; orphan_sweep as
  the `orphan-sweep` subcommand), `storage.rs::{delete_object_version,list_objects_page}`.
  Live-verified vs Postgres + SeaweedFS (admin CRUD/stats/settings + 403/401 guard;
  quota-reconcile + uploads-sweeper boot ticks corrected drift / reaped a real stale
  multipart; orphan-sweep dry-run→delete→clean over a real orphaned asset blob).

## Next action — Phase 3 slice 8 (verification & cutover) in `kutup-server`

1. Re-implement the 21 Go `*_test.go` suites in Rust against a per-test Postgres schema
   (port `backend/internal/testdb`); `cargo test -p kutup-server` green.
2. Run the Rust server against a fresh DB + the SeaweedFS S3; drive it with the Rust **and**
   Go CLI and the frontend Playwright flows — behaviour must match the Go backend.
3. Regenerate the OpenAPI spec via utoipa and diff the endpoint set against
   `backend/docs/swagger.yaml` (43 routes + 1 WS) — must match.
   Then Part C (cutover): swap docker-compose/nginx to the Rust binary, remove `backend/`
   and `cmd/kutup/`, update the docs.

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
