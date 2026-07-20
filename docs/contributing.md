# Contributing

Contributions are welcome. This guide covers local development setup for both the backend and frontend.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust | 1.91+ (stable) | https://rustup.rs/ |
| Node.js | 20+ | https://nodejs.org/ |
| pnpm | 9+ | `npm install -g pnpm` |
| Docker + Compose v2 | latest | https://docs.docker.com/get-docker/ |

---

## Local Development Setup

### 1. Clone and configure

```sh
git clone https://github.com/kutupbulut/kutup.git
cd kutup
cp .env.example .env
# Fill in required values — see README for the configuration table
```

### 2. Start infrastructure (database + storage)

The easiest approach is to run the full stack and then replace only the service you're working on:

```sh
docker compose up -d --build
```

For faster iteration, you can run just the infrastructure services and run the backend/frontend natively:

```sh
docker compose up -d postgres seaweedfs-master seaweedfs-volume seaweedfs-filer seaweedfs-s3 seaweedfs-init
```

---

## Backend Development

The backend is a Rust application — `crates/kutup-server` (Axum + sqlx + aws-sdk-s3) in the
root Cargo workspace. It shares the E2EE primitives with the CLI via `crates/kutup-crypto`.

### Running natively

```sh
# Export env vars (or use a tool like direnv)
export DATABASE_URL="postgres://kutup:<POSTGRES_PASSWORD>@localhost:5432/kutup?sslmode=disable"
export JWT_SECRET="<your-jwt-secret-32+chars>"
export S3_ENDPOINT="http://localhost:8333"
export S3_ACCESS_KEY="kutup"
export S3_SECRET_KEY="<your-s3-secret>"
export S3_BUCKET="kutup-files"
export S3_REGION="us-east-1"
export APP_ENV="development"

cargo run -p kutup-server          # or: cargo build --release -p kutup-server
```

The backend starts on `http://localhost:3000`. The binary also has an `orphan-sweep`
subcommand (`cargo run -p kutup-server -- orphan-sweep [--delete]`) for GC'ing orphaned S3
blobs.

> You need to expose the SeaweedFS S3 port to the host. Add `ports: ["8333:8333"]` to the `seaweedfs-s3` service in `docker-compose.yml` temporarily for local dev.

### Database migrations

Migrations live in `crates/kutup-server/migrations/` (`<N>_<name>.up.sql` / `.down.sql` —
sqlx's reversible format) and are **embedded into the binary at compile time** via
`sqlx::migrate!()`, then applied automatically on startup.

To add a migration, create the pair by hand (or with the sqlx CLI):

```sh
cargo install sqlx-cli --no-default-features --features postgres   # one-time
sqlx migrate add -r <migration_name> --source crates/kutup-server/migrations
```

Write the forward migration in `.up.sql` and the rollback in `.down.sql`. Because migrations
are embedded at compile time, **rebuild** the server after adding one.

### OpenAPI

The server generates its OpenAPI document with [`utoipa`](https://github.com/juhaku/utoipa)
and serves the machine-readable JSON at `GET /api-docs/openapi.json`. Per-path operation
annotations and an interactive Swagger UI are deferred (see `docs/roadmap.md`); the document
currently carries the info block, the `BearerAuth` security scheme, and the response schemas.

### Running tests

```sh
cargo test                                      # all crates
cargo test -p kutup-crypto                      # crypto byte-parity vectors
cargo clippy --all-targets -- -D warnings       # lints (gate)
cargo fmt --check                               # formatting (gate)
./scripts/test-chat-federation.sh               # isolated two-server federation + outage/restart
```

The federation harness uses its own Compose project, two tmpfs Postgres
databases, and host ports 39081/39082. In addition to delivery/retry, it checks
all four admission modes, directional domain rules, disabled discovery and
capabilities, and policy audit entries. It tears the topology down on exit and
does not touch the ordinary development stack. Set
`KUTUP_FEDERATION_SKIP_BUILD=1` only when reusing an image already built from
the current server sources.

---

## Frontend Development

The frontend is a React 18 + TypeScript app in `frontend/`, built with Vite.

### Running natively

```sh
cd frontend
pnpm install
pnpm dev
```

Vite starts on `http://localhost:5173`. The `vite.config.ts` includes a proxy rule that forwards `/api` requests to the backend at `http://localhost:3000`, so you can develop against a running backend without CORS issues.

### Building for production

```sh
pnpm build
```

Output goes to `frontend/dist/`, which is then served by the frontend Nginx container.

### TypeScript

The project uses strict TypeScript (`"strict": true` in `tsconfig.json`). All new code must type-check cleanly. Run the type checker:

```sh
pnpm tsc --noEmit
```

---

## Project Structure

```
kutup/
├── Cargo.toml               # Root Cargo workspace (backend + CLI + crypto)
├── Dockerfile.server        # Build image for the Rust kutup-server
├── crates/
│   ├── kutup-server/        # Backend API (Axum + sqlx + aws-sdk-s3)
│   │   ├── src/main.rs      # Server setup, route registration, layers, subcommands
│   │   ├── src/handlers/    # HTTP handlers (one file per domain)
│   │   ├── src/{jwt,totp,ssrf,ratelimit,middleware}.rs  # auth, rate limiting, SSRF guard
│   │   ├── src/{storage,jobs,hub}.rs  # S3 client, background jobs, collab room hub
│   │   ├── src/{models,error,config,db,openapi}.rs
│   │   └── migrations/      # SQL migrations (embedded via sqlx::migrate!())
│   ├── kutup-cli/           # The `kutup` CLI (clap)
│   │   └── src/{commands,api,session,syncengine,transfer}/  # commands, HTTP client, session store, sync
│   └── kutup-crypto/        # Shared E2EE primitives (dryoc + RustCrypto)
│       ├── src/{kdf,secretbox,sealedbox,stream,asset,envelope,mnemonic}.rs
│       └── tests/vectors/   # Checked-in byte-parity vectors
├── frontend/
│   ├── src/
│   │   ├── api/client.ts    # Axios instance with auth interceptors
│   │   ├── crypto/          # All libsodium wrappers (symmetric, asymmetric, KDF, mnemonic)
│   │   ├── collab/          # Envelope, transport, AEAD frame helpers (collab WS layer)
│   │   ├── components/editors/
│   │   │   ├── TextCollabEditor.tsx       # Notes / code (CodeMirror 6 + Yjs)
│   │   │   ├── office/OfficeEditor.tsx    # .docx/.xlsx/.pptx (OnlyOffice bridge)
│   │   │   └── whiteboard/WhiteboardEditor.tsx  # .excalidraw (Excalidraw + last-write-wins)
│   │   ├── pages/           # Route-level components (Drive, FileEditorPage, Settings, Admin, …)
│   │   ├── store/           # Redux slices (auth state)
│   │   └── workers/         # Web Worker for Argon2id KDF
│   ├── public/onlyoffice/   # CryptPad-pinned OnlyOffice bundle (gitignored; install via script)
│   └── vite.config.ts       # Dev server proxy config
│   (CLI commands: register, login, ls, upload, download, sync, share, versions, devices, 2fa, pub, mv, color;
│    redb session store, device key in the OS keyring on macOS/Windows or a chmod-600 file on Linux)
├── src-tauri/                # Tauri 2 shell (desktop + iOS/Android) — see docs/desktop-build.md, docs/mobile-build.md
│   ├── src/lib.rs           # Plugin setup + OS-keychain vault commands (vault_set/get/delete)
│   ├── tauri.conf.json      # Bundle id (dev.kutup.client), mainBinaryName (kutup-client), targets, scopes
│   └── capabilities/        # Tauri permission capabilities (default.json + desktop.json)
├── nginx/nginx.conf          # Production Nginx config
├── docs/                     # Documentation
└── docker-compose.yml
```

---

## Operations

### Orphan-blob sweep

Periodic admin task that walks SeaweedFS for blobs whose containing `files.id` row no longer exists (PUT-then-crash leftovers, residual snapshot blobs from before quota tracking, etc.) and deletes them.

Subcommand on the existing `kutup-server` binary — same Docker image, same env vars, same DB pool.

**Always start with a dry-run.** Default behaviour reports orphans without touching them.

```sh
# Dry-run (default). Lists orphans + summary; no deletions.
docker compose exec backend ./kutup-server orphan-sweep

# Tighter age window for testing — anything older than 1h is fair game.
docker compose exec backend ./kutup-server orphan-sweep --age-floor=1h

# After verifying the dry-run output looks right, actually delete.
docker compose exec backend ./kutup-server orphan-sweep --delete
```

**Flags:**

| Flag | Default | Notes |
|------|---------|-------|
| `--delete` | `false` | Without this, the command is a dry-run. |
| `--age-floor` | `24h` | Skip blobs younger than this. The 24h default absorbs in-flight uploads; lower it only for testing. |
| `--page-sleep` | `200ms` | Sleep between S3 LIST pages. |
| `--prefix` | `files/` | S3 key prefix to walk. |

**Reading the summary log:**

```
orphan-sweep summary: pages=N keys=N orphans=N skipped-age=N skipped-shape=N deleted=N bytes-reclaimed=N mode=dry-run|delete
```

- `skipped-age` should be > 0 on a healthy bucket (the in-flight upload window). If it's 0 every run, the age floor isn't engaging — investigate before relying on the result.
- `skipped-shape` counts keys outside the `files/<UUID>/...` shape; the sweep never deletes these.
- `bytes-reclaimed` is the projected (dry-run) or actual (`--delete`) byte savings.

The sweep does **not** persist progress — a crash mid-run means rerunning from scratch. Acceptable at current scale; revisit if the bucket grows past ~500K objects.

---

## Code Conventions

### Backend (Rust)

- Axum handlers organized by domain (`crates/kutup-server/src/handlers/` — auth, collections, files, shares, federation, admin, …). Each file opens with a `//!` doc comment.
- Use `sqlx` runtime queries (`sqlx::query`/`query_as`) — no compile-time-checked macros (no live DB at build), no ORM.
- All cryptographic operations are the client's responsibility; the backend must never attempt to decrypt anything. Shared primitives live in `crates/kutup-crypto`.
- SSRF validation (`crates/kutup-server/src/ssrf.rs`) must be applied to all user-supplied URLs before making outbound requests (federation).
- Gate every change with `cargo clippy --all-targets -- -D warnings` + `cargo fmt` + `cargo test`.

### Frontend (TypeScript)

- Strict mode is enforced. No `any` types.
- All cryptographic operations go in `src/crypto/`. Components and pages must not call libsodium directly.
- KDF (Argon2id) runs in `src/workers/kdf.worker.ts` to avoid blocking the main thread.
- State management uses Redux Toolkit slices. Keep slices thin — business logic goes in thunks or service functions.
- API calls go through `src/api/client.ts`, which handles token injection and refresh.

---

## Submitting Changes

1. Fork the repository and create a feature branch from `master`.
2. Make focused, well-described commits. Each commit should be buildable and leave tests passing.
3. Open a pull request against `master`. Describe **why** the change is needed, not just what it does.
4. For security-related changes (cryptography, authentication, federation), include a brief explanation of the security model impact.

For bug reports and feature requests, open a GitHub issue.
