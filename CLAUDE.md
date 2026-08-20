# CLAUDE.md — working in the kutup repo

Read this first; it's the entry point. Then skim `docs/` for anything you'll touch.

## What kutup is

End-to-end encrypted, self-hosted Drive, real-time collaboration, and federated Chat. Files, private metadata, document edits, Chat content/media, and protected Chat history are encrypted client-side; servers still see the operational metadata required for accounts, routing, timing, sizes, federation, and quotas. A random account master key is wrapped for password login and the separate 24-word recovery path. Stack: **Rust (Axum)** backend (`crates/kutup-server`, binary **`kutup-server`**), **React/Vite** SPA, **SeaweedFS** (S3-compatible) for blobs, **tus.io 1.0** resumable uploads, canonical Rust/WASM crypto, **libsignal** Direct Chat, **OpenMLS** private groups, **Yjs** CRDTs for text, **OnlyOffice** (client-only, CryptPad-style) for office docs, and **Excalidraw** for whiteboards. Also: a **Tauri 2** desktop shell with retained experimental mobile targets (`src-tauri/`) and a **Rust CLI** (`crates/kutup-cli`, binary **`kutup`**). The dedicated native apps are separate work in progress. Drive and Chat use one authenticated federation stack. *(The original Go backend + Go CLI were rewritten in Rust and removed; the `docs/rust-conversion/` tree is historical.)*

## Where to read

- `README.md` — feature tour and quick start.
- `docs/README.md` — documentation map and the distinction between current,
  normative, historical, research, and plan documents.
- `docs/architecture.md` — system design (the E2EE model, the collab WS layer, federation).
- `docs/api.md` — REST API. The server emits its full OpenAPI spec (every operation annotated via `#[utoipa::path]`) at `GET /api-docs/openapi.json`; an interactive Swagger UI is deferred (see `docs/roadmap.md`).
- `docs/contributing.md` — local dev setup, the full project structure, code conventions, ops scripts.
- `docs/desktop-build.md` — the Tauri app: build, the OnlyOffice-strip, server-picker, OS keychain, CORS, cutting (pre)releases.
- `docs/onlyoffice.md` — how office docs stay client-side (the CryptPad pattern: OnlyOffice in the browser, **no WOPI / no Collabora**).
- `docs/chat-protocol.md`, `docs/chat-media.md`, `docs/chat-backup.md` — current Chat, attachment, and continuous-history contracts; the matching `*-security-threat-model.md` files define their trust boundaries.
- `docs/self-hosting.md`, `docs/test/curl.md`.
- `docs/roadmap.md` — **production-readiness backlog and phase gate record**. Sits between current-state `docs/*.md` and forward-looking `docs/research/`. Read it before adding a deferred feature or stub.
- `docs/research/` — time-stamped research, including both forward-looking
  ideas and historical investigations that led to shipped work. Do not treat a
  research baseline as current behavior; follow its current-reference links.
- Recent `git log` + open PRs (`gh pr list`) — what changed lately; do not use a
  historical PR number as a current-state reference.

## Repo layout (top level)

`crates/` the Rust Cargo workspace — `kutup-server` (Axum API, binary **`kutup-server`**; migrations under `crates/kutup-server/migrations/`), `kutup-cli` (binary **`kutup`**), `kutup-crypto` (shared E2EE primitives), plus the excluded standalone `kutup-chat-core` and `kutup-client-ffi` · `frontend/` React SPA + editors · `src-tauri/` Tauri 2 desktop shell (binary **`kutup-client`**) · dedicated native apps live in sibling repos `kutup-ios` and `kutup-android` and consume the generated bindings · `nginx/` prod config · `Dockerfile.server` · `docker-compose*.yml` · `docs/`.

## Dev workflow (cheat-sheet — full detail in `docs/contributing.md`)

- **Full stack:** `cp .env.example .env` (fill it in), put `fullchain.pem` and `privkey.pem` under `nginx/certs/` (the self-signed development command is in `README.md`), then `docker compose up -d --build --wait` → nginx serves **`https://localhost:38443`** and redirects port 38080. For faster iteration, run only infra in Docker and the backend/frontend natively — see `docs/contributing.md`.
- **Frontend:** `pnpm -C frontend dev` · `pnpm -C frontend test` (vitest) · `pnpm -C frontend exec tsc --noEmit`. Every new user-facing string **must** be added to `frontend/src/locales/en.json` *and* `tr.json` in the same change — no hard-coded English in JSX.
- **Backend:** `cargo build -p kutup-server` · `cargo test` · `cargo clippy --all-targets -- -D warnings` · `cargo fmt`. Migrations live in `crates/kutup-server/migrations/` (embedded at compile time via `sqlx::migrate!()`; reversible `.up/.down.sql`). The server binary also has an `orphan-sweep` subcommand. Required env: `DATABASE_URL`, `JWT_SECRET` (≥32 chars), `S3_ENDPOINT`/`S3_ACCESS_KEY`/`S3_SECRET_KEY`; see `.env.example` for optional storage, retention, chat, and rate-limit settings.
- **Desktop app:** `pnpm tauri:build` → bundles in `src-tauri/target/release/bundle/`. (`pnpm tauri:dev` for the dev loop.) See `docs/desktop-build.md` first — there are real memory/OnlyOffice constraints.
- **Native apps:** iOS and Android are work in progress in the sibling
  `kutup-ios` / `kutup-android` repos and are not release-ready (they are not
  the retained Tauri mobile targets). Their plans define the platform
  UI/Keychain/Keystore layers; shared Signal protocol logic comes from
  `kutup-chat-core` through `kutup-client-ffi`. See `docs/mobile-build.md` and
  `docs/chat-native-bindings.md`; generate Swift/Kotlin sources with
  `scripts/generate-native-bindings.sh`.
- **CLI:** `cargo run -p kutup-cli -- …` (or `cargo build --release -p kutup-cli` → `target/release/kutup`). Unlike the old Go CLI, the Rust CLI has a `register` subcommand (creates an account end-to-end, client-side crypto + a printed 24-word recovery phrase) and reads `KUTUP_PASSWORD` for non-interactive login/register.
- **Releases are tag-triggered** (CI on `master`): `v*` → CLI built for Linux/macOS/Windows (amd64+arm64) via a cargo matrix (`.github/workflows/release.yml`, using `taiki-e/upload-rust-binary-action`); `desktop-v*` → desktop installers (`.deb`/`.rpm`/`.AppImage`/`.dmg`/`.msi`) via `tauri-action`, drafting a GitHub Release (`.github/workflows/release-desktop.yml`). A `-alpha.N` / `-beta.N` / `-rc.N` segment ⇒ the release is flagged "Pre-release". Builds are currently **unsigned**.
- **e2e / Playwright repros** run against the running dev stack at `https://localhost:38443`. The frontend container **bakes `dist/`**, so a bare local frontend build is not visible until the image is rebuilt. Reproduce required gates locally before spending GitHub CI: `scripts/test-chat-backup-integration.sh` for real Postgres/SeaweedFS lifecycle and `scripts/test-chat-federation.sh` for the complete two-server API/browser gate. Playwright retries remain zero; sensitive Chat/backup runs use the sanitized-artifact mode documented in `tests/e2e/README.md`.

## Conventions & non-obvious context

- **Pre-production, not pre-quality**: there are no public releases yet (until the first `v*` / `desktop-v*` tag). Breaking changes are fine — rename freely, change DB schema directly, no need to write migrations for every change yet. But: **the bar for "this is done" is production-grade.** When you ship a UI affordance, wire it end-to-end — no silent stubs, no toasts pointing at SQL workarounds. If a feature can't be wired end-to-end yet (because a backend slice is missing, etc.), **don't ship the affordance** — add the gap to `docs/roadmap.md` and skip the UI entry until the slice lands. The user's standing direction: *"we need proper production-ready app, dont try to ship fast"*.
- **Office docs** (`.docx`/`.xlsx`/`.pptx`) collab uses the **CryptPad pattern** — OnlyOffice runs entirely in the browser; document state is never decrypted server-side. No WOPI, no Collabora. (`docs/onlyoffice.md`.)
- **Tauri build memory constraint**: `tauri::generate_context!()` embeds *all*
  of `frontendDist` as a static byte array; the ~2.6 GB OnlyOffice SDK is
  stripped by `pnpm -C frontend build:tauri` before that embed (otherwise
  `rustc` OOMs). Consequently the desktop bundle and experimental Tauri-mobile
  wrapper cannot open Office docs. This does not define the separate native
  apps' final architecture. The shell crate builds at `opt-level = 1`;
  `[lib] crate-type = ["staticlib", "cdylib", "rlib"]`.
- **Bundle identity**: `identifier` `dev.kutup.client` (reserved product-wide),
  `mainBinaryName` `kutup-client`, `productName` `Kutup`, desktop app-data dir
  `$APPDATA/dev.kutup.client/`, OS-keychain service `dev.kutup.client` in the
  Tauri shell. The native clients' Keychain/Keystore integration is work in
  progress. The CLI's keychain service is the separate `kutup-cli`.
- **Rust owns Kutup cryptographic formats**: `crates/kutup-crypto/` (`dryoc` + RustCrypto) is canonical for suite dispatch, headers, derivation labels, validation and policy. The browser consumes it through `kutup-crypto-wasm`; CLI and native clients call the same Rust code. A narrow browser libsodium primitive adapter is allowed only under the measured 10×/platform-failure exception in `docs/cryptographic-dependencies.md`, and never owns a persistent format. Checked-in vectors live in `crates/kutup-crypto/tests/vectors/*.json`; run Rust and WASM vector tests after every crypto change. **Never** silently change a V1 suite fact: Argon2id parameters are persisted per account; secretstream uses 5 MiB chunks and authenticated `TAG_FINAL`; signatures use strict verification; recovery uses the BIP39 English encoding of 32 random bytes. Before the first stable tag development data may be recreated; afterward any byte-changing update requires a new suite and explicit read/migrate policy.
- **Go→Rust rewrite — DONE** (branch `claude/go-rust-rewrite-G16zO`): the former Go backend (`backend/`) and Go CLI (`cmd/kutup/`) were rewritten in Rust under the root Cargo workspace (`crates/`) and **removed**. The Rust server is at full route + behaviour parity with the old Go backend (verified by a differential CLI battery driving both the old Go CLI and the Rust CLI against both servers), and the Rust CLI reached full parity with the old Go CLI (incl. `.excalidraw` asset extraction/hydration) and has since grown beyond it: `register`, `recover`, `trash`, `mv --folder`, resumable uploads, a three-way-merge `sync` engine, uniform `--json` + differentiated exit codes. `src-tauri/` stays excluded from the workspace. Remaining deferrals are tracked in `docs/roadmap.md` (interactive Swagger UI; CLI follow-ups). See `docs/rust-conversion/` for the slice-by-slice conversion history.
- **CORS**: the backend uses an env-driven `ALLOWED_ORIGINS` allowlist (not `*`) because `withCredentials` (refresh-cookie) is incompatible with the wildcard; the Tauri origins (`tauri://localhost`, `http://tauri.localhost`) are in the default list.

## Working with the user

- When you summarize a doc, spec, PR, or file, paste the salient content **inline in the chat** — don't make the user open a file just to learn what's in it.
- Keep `docs/` current when behavior changes; put forward-looking design/research under `docs/research/`.
