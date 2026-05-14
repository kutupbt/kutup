# CLAUDE.md — working in the kutup repo

Read this first; it's the entry point. Then skim `docs/` for anything you'll touch.

## What kutup is

End-to-end encrypted, self-hosted "Google Drive" with **real-time collaboration** for notes/code, office docs, and whiteboards. The server only ever sees ciphertext — files, filenames, folder structure, document edits, and cursor positions are all encrypted client-side; keys are derived in-browser from the user's password + a 24-word recovery phrase. Stack: **Go (Fiber)** backend, **React/Vite** SPA, **SeaweedFS** (S3-compatible) for blobs, **tus.io 1.0** resumable uploads, **libsodium** (`crypto_secretstream_xchacha20poly1305` for files, AEAD + Ed25519-signed frames for collab), **Yjs** CRDTs for text, **OnlyOffice** (client-only, CryptPad-style) for office docs, **Excalidraw** for whiteboards. Also: a **Tauri 2** desktop/mobile shell (`src-tauri/`) and a **Go (Cobra) CLI** (`cmd/kutup/`). Federation lets you share a folder with a user on a different kutup server without either backend seeing plaintext.

## Where to read

- `README.md` — feature tour + the env-var configuration table.
- `docs/architecture.md` — system design (the E2EE model, the collab WS layer, federation).
- `docs/api.md` — REST API; `backend/docs/` is the generated OpenAPI spec (`swag init`).
- `docs/contributing.md` — local dev setup, the full project structure, code conventions, ops scripts.
- `docs/desktop-build.md` — the Tauri app: build, the OnlyOffice-strip, server-picker, OS keychain, CORS, cutting (pre)releases.
- `docs/onlyoffice.md` — how office docs stay client-side (the CryptPad pattern: OnlyOffice in the browser, **no WOPI / no Collabora**).
- `docs/self-hosting.md`, `docs/test/curl.md`.
- `docs/research/` — **forward-looking** design/research notes (vs. everything else under `docs/` = **current-state** reference). Don't treat `docs/research/` as describing what's shipped.
- Recent `git log` + open PRs (`gh pr list`) — what changed lately. The Tauri 2 desktop app v1 landed in **PR #18**.

## Repo layout (top level)

`backend/` Go Fiber API · `frontend/` React SPA + the editors · `src-tauri/` Tauri 2 shell — desktop + iOS/Android (binary **`kutup-client`**; see `docs/desktop-build.md`, `docs/mobile-build.md`) · `cmd/kutup/` Go CLI (binary **`kutup`**) · `nginx/` prod config · `docker-compose*.yml` · `docs/`.

## Dev workflow (cheat-sheet — full detail in `docs/contributing.md`)

- **Full stack:** `cp .env.example .env` (fill it in) then `docker compose up -d --build` → nginx serves the app at **`https://localhost:38443`** (self-signed cert). For faster iteration, run only infra in Docker and the backend/frontend natively — see `docs/contributing.md`.
- **Frontend:** `pnpm -C frontend dev` · `pnpm -C frontend test` (vitest) · `pnpm -C frontend exec tsc --noEmit`. Every new user-facing string **must** be added to `frontend/src/locales/en.json` *and* `tr.json` in the same change — no hard-coded English in JSX.
- **Backend:** `cd backend && go test ./...`. Migrations live in `backend/db/migrations/` (but see "pre-production" below).
- **Desktop app:** `pnpm tauri:build` → bundles in `src-tauri/target/release/bundle/`. (`pnpm tauri:dev` for the dev loop.) See `docs/desktop-build.md` first — there are real memory/OnlyOffice constraints.
- **Mobile app:** `pnpm tauri:ios:init` / `tauri:android:init` (once), then `tauri:ios:dev` / `tauri:android:dev` (simulator/emulator) and `tauri:ios:build` / `tauri:android:build`. iOS needs a Mac (Xcode); Android works on Linux too. `src-tauri/gen/` is gitignored. See `docs/mobile-build.md`. iOS session persistence is wired (OS-keychain via `keyring`'s `apple-native` backend); Android session persistence is still a stub (no `keyring` Android backend) and re-logs in on each launch.
- **CLI:** `go run ./cmd/kutup …` (or `go build -o /tmp/kutup ./cmd/kutup`).
- **Releases are tag-triggered** (CI on `master`): `v*` → CLI via GoReleaser (`.github/workflows/release.yml`); `desktop-v*` → desktop installers (`.deb`/`.rpm`/`.AppImage`/`.dmg`/`.msi`) via `tauri-action`, drafting a GitHub Release (`.github/workflows/release-desktop.yml`). A `-alpha.N` / `-beta.N` / `-rc.N` segment ⇒ the release is flagged "Pre-release". Builds are currently **unsigned**.
- **e2e / Playwright repros** run against the running dev stack at `https://localhost:38443`. Note: the `kutup-frontend-1` container **bakes `dist/`**, so a bare `pnpm -C frontend build` won't be visible to Playwright until you `docker compose build frontend` (or run the frontend natively against the stack).

## Conventions & non-obvious context

- **Pre-production**: there are no public releases yet (until the first `v*` / `desktop-v*` tag). Breaking changes are fine — rename freely, change DB schema directly, no need to write migrations for every change yet.
- **Office docs** (`.docx`/`.xlsx`/`.pptx`) collab uses the **CryptPad pattern** — OnlyOffice runs entirely in the browser; document state is never decrypted server-side. No WOPI, no Collabora. (`docs/onlyoffice.md`.)
- **Desktop build memory constraint**: `tauri::generate_context!()` embeds *all* of `frontendDist` as a static byte array; the ~2.6 GB OnlyOffice SDK is stripped by `pnpm -C frontend build:tauri` before that embed (otherwise `rustc` OOMs). Consequence: the app **can't open Office docs in v1** (desktop or mobile). The shell crate builds at `opt-level = 1`; `[lib] crate-type = ["staticlib", "cdylib", "rlib"]` (rlib = desktop binary, staticlib/cdylib = iOS/Android FFI). Follow-up: load the SDK from `${serverUrl}/onlyoffice/…` so the app streams it from the user's server.
- **Bundle identity**: `identifier` `dev.kutup.client` (product-wide — desktop + iOS + Android), `mainBinaryName` `kutup-client`, `productName` `Kutup`, desktop app-data dir `$APPDATA/dev.kutup.client/`, OS-keychain service `dev.kutup.client` (= `KEYRING_SERVICE` in `src-tauri/src/lib.rs`; desktop only — no mobile keychain yet). The CLI's keychain service is the separate `kutup-cli`.
- **The crypto must stay mirrored**: `frontend/src/crypto/` and `cmd/kutup/internal/crypto/` implement the same primitives (KDF, secretstream framing, mnemonic, asymmetric) — keep them in sync when you change one.
- **CORS**: the backend uses an env-driven `ALLOWED_ORIGINS` allowlist (not `*`) because `withCredentials` (refresh-cookie) is incompatible with the wildcard; the Tauri origins (`tauri://localhost`, `http://tauri.localhost`) are in the default list.

## Working with the user

- When you summarize a doc, spec, PR, or file, paste the salient content **inline in the chat** — don't make the user open a file just to learn what's in it.
- Keep `docs/` current when behavior changes; put forward-looking design/research under `docs/research/`.
