# Kutup

> Self-hosted, end-to-end encrypted file storage with federation

![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)
![TypeScript](https://img.shields.io/badge/TypeScript-5.4-3178C6?logo=typescript)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)
![License](https://img.shields.io/badge/License-AGPL--3.0--only-green)

Kutup is a privacy-first file storage and real-time collaboration platform where the server never sees your data. All encryption and decryption happens in the browser using [libsodium](https://libsodium.org/) — files, filenames, folder structures, collaborative document state, even cursor presence are end-to-end encrypted. You own your keys; the server stores only ciphertext.

---

## Features

### Storage and sharing
- **End-to-end encryption** — files and metadata encrypted client-side with libsodium before upload; server stores only ciphertext
- **Streaming chunked encryption** — large files via `crypto_secretstream_xchacha20poly1305`; no whole-file ciphertext in memory
- **Folder hierarchy** — nested collections with arbitrary depth
- **Folder color coding** — visual organization for collections
- **Public share links** — token-based, no account needed for recipients
- **Collection sharing** — share folders with other users; per-user permissions (read / upload / delete) with optional upload quota
- **Cross-server federation** — share collections with users on other Kutup instances; AGPL-licensed federation flow with explicit invite tokens
- **File version history** — every save creates a versioned snapshot; restore any prior version

### Real-time collaboration
- **End-to-end encrypted notes** — Markdown / code editor (CodeMirror 6 + Yjs) with live multi-user cursors, awareness, selection sharing
- **End-to-end encrypted office docs** — `.docx` / `.xlsx` / `.pptx` via the OnlyOffice editor running fully client-side (CryptPad pattern); document state never decrypted on the server
- **Live cell-selection presence** — peer cell ranges shown as translucent colored rectangles in xlsx; mirrors CryptPad's UX
- **Per-user presence color** — pick a color in Settings or the editor toolbar; the same color follows you across notes, office docs, and devices
- **Cross-tab session sync** — open the same file in multiple tabs; `BroadcastChannel` keeps presence color, auth, and color-picker state in step without a reload

### Auth, identity, recovery
- **Multi-device** — per-device Ed25519 keypair, individually revocable from Settings; no password leaves the browser
- **Two-factor authentication** — TOTP (compatible with any authenticator app)
- **Account recovery** — 24-word BIP39 mnemonic recovery phrase encrypts the master key; recovery bypasses 2FA (the phrase IS the second factor)
- **i18n** — English + Turkish UI translations; every user-facing string keyed in `en.json` / `tr.json`

### Operations
- **Admin dashboard** — user management, storage statistics, global settings (registration enable/disable, etc.)
- **Zero-knowledge server** — server never sees plaintext keys, filenames, file contents, or document edits
- **Storage quotas** — per-user storage limits configurable by admins
- **Swagger / OpenAPI** — interactive API explorer at `/swagger/index.html`
- **Playwright e2e suite** — covers auth, collab, office sync, multi-tab races

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Go 1.25, [Fiber v2](https://gofiber.io/) (HTTP + WebSocket), [pgx v5](https://github.com/jackc/pgx), PostgreSQL 16 |
| Frontend | React 18, TypeScript 5.4, Vite 5, [Redux Toolkit 2](https://redux-toolkit.js.org/), [TailwindCSS](https://tailwindcss.com/) + [Radix UI](https://www.radix-ui.com/) |
| Crypto | [libsodium-wrappers-sumo](https://github.com/jedisct1/libsodium.js) 0.7 (Argon2id, XChaCha20-Poly1305 AEAD, Ed25519, NaCl box / secretbox / secretstream) |
| Realtime collab | [Yjs](https://yjs.dev/) 13 + `y-codemirror.next` for notes; OnlyOffice editor + `x2t` WASM converter for office; custom Go WebSocket relay with per-frame AEAD envelopes |
| Storage | [SeaweedFS](https://github.com/seaweedfs/seaweedfs) (S3-compatible object storage) |
| Infrastructure | Docker Compose, Nginx (TLS termination + static asset serving) |
| Testing | Playwright 1.59 (e2e), Go `testing` (unit + integration), Vitest (frontend unit) |

---

## Quick Start

**Requirements:** Docker 24+ and Docker Compose v2.

```sh
# 1. Clone
git clone https://github.com/alperen-albayrak/kutup.git
cd kutup

# 2. Configure
cp .env.example .env
# Edit .env — at minimum set strong values for:
#   POSTGRES_PASSWORD, JWT_SECRET, S3_SECRET_KEY, ADMIN_ACCOUNTS

# 3. Start
docker compose up -d --build

# 4. Find your admin password
docker compose logs backend | grep -i admin
```

Open `http://localhost` in your browser. Log in with the admin credentials you set in `ADMIN_ACCOUNTS`. On first login you will be prompted to complete setup (generate and save your recovery phrase).

---

## Configuration

All configuration is done via environment variables. Copy `.env.example` to `.env` and edit the values.

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `POSTGRES_DB` | PostgreSQL database name | `kutup` | No |
| `POSTGRES_USER` | PostgreSQL username | `kutup` | No |
| `POSTGRES_PASSWORD` | PostgreSQL password | — | **Yes** |
| `JWT_SECRET` | Secret for signing JWTs. Generate with `openssl rand -hex 64` | — | **Yes** |
| `S3_ENDPOINT` | URL of the S3 gateway (set automatically inside Docker; only needed when running the backend natively) | `http://seaweedfs-s3:8333` | For native dev |
| `S3_ACCESS_KEY` | SeaweedFS S3 access key | `kutup` | No |
| `S3_SECRET_KEY` | SeaweedFS S3 secret key | — | **Yes** |
| `S3_BUCKET` | S3 bucket name | `kutup-files` | No |
| `S3_REGION` | S3 region (cosmetic for SeaweedFS) | `us-east-1` | No |
| `APP_ENV` | Application environment | `production` | No |
| `SERVER_URL` | Public base URL of this server — **required for federation** | `http://kutup.local` | For federation |
| `ADMIN_ACCOUNTS` | Comma-separated `email:username:password` triples for bootstrap admins | — | **Yes** |

> The same `S3_ACCESS_KEY` and `S3_SECRET_KEY` values must appear in `seaweedfs-s3.json`.

---

## Architecture Overview

Kutup uses a layered key hierarchy where the server is entirely zero-knowledge:

```
mnemonic → recovery key → encrypted master key
                                  ↓ (decrypt)
                            master key
                                  ↓ (encrypts)
                    per-collection key (random, XSalsa20-Poly1305 via NaCl secretbox)
                                  ↓ (encrypts)
                         per-file key (random) → encrypted file content
```

For collection sharing, a NaCl box keypair is generated per user. The sharer encrypts the collection key to the recipient's public key.

For real-time collaboration, every collab frame (Yjs update, awareness, OnlyOffice op, OnlyOffice cursor) is wrapped in an AEAD envelope before it leaves the browser:

```
content_key = HKDF-SHA256(collection_master_key, salt="kutup/file-content/v1", info=fileId)

[ frame ] = ciphertext (XChaCha20-Poly1305 AEAD over plaintext, AAD = 30-byte header)
            + 30-byte header (version, kind, docKeyId, senderDeviceId, sequence, nonce-prefix)
            + 64-byte Ed25519 signature (signs header + ciphertext with sender's device key)
```

The Go relay sees only the opaque ciphertext + signature; it routes by `fileId` and `kind`, persists `OO_OP` / `Yjs_update` to `file_update_log` for replay-on-reconnect, and broadcasts ephemeral kinds (`OO_CURSOR`, `Yjs_awareness`, etc.) without persistence. The server never holds a key that can decrypt anything.

See [docs/architecture.md](docs/architecture.md) for the full design including the login flow, federation model, storage layer, and the collab wire protocol.

---

## Self-Hosting Guide

For production deployment with TLS, reverse proxies, and backup strategies, see [docs/self-hosting.md](docs/self-hosting.md).

---

## Optional: OnlyOffice for `.docx` / `.xlsx` / `.pptx`

The collaborative office-document editor is an optional integration with [OnlyOffice](https://github.com/cryptpad/onlyoffice-editor) (the CryptPad fork). All editing happens **fully client-side** — the server only relays opaque AEAD-encrypted frames between peers. Document state is never decrypted server-side.

What works today:
- Real-time multi-user editing of `.docx`, `.xlsx`, `.pptx`.
- Cell-level operations in xlsx (typing, fill color, formatting, conditional formatting, merges, etc.) sync between peers.
- **Live cell-selection presence** — peers see each other's selected cell ranges as translucent colored rectangles (CryptPad-parity).
- **Per-user color** — pick once in Settings (or the editor toolbar); the same color labels you across notes, all office docs, and all your tabs.
- **Multi-tab differentiation** — the same user with two tabs open shows up as `username #abcd` and `username #ef01` in OnlyOffice's peer chrome.
- File-version history, save-on-close, multi-device.

| Path | License |
|---|---|
| All kutup source | **AGPL-3.0-only** |
| `frontend/public/onlyoffice/inner.html`, `frontend/src/components/editors/office/` (kutup ↔ OnlyOffice bridge) | **AGPL-3.0-or-later** (so they can link the OnlyOffice client) |
| `frontend/public/onlyoffice/dist/` (downloaded OnlyOffice editor build, gitignored) | **AGPL-3.0-or-later** (upstream, unchanged) |

To enable office editing, run:

```sh
./install-onlyoffice.sh
```

That populates `frontend/public/onlyoffice/{dist,templates}/` (gitignored). Rebuild the frontend afterwards. Without this step, kutup still runs — `.docx` / `.xlsx` / `.pptx` files just stay download-only.

Details:
- License boundary: [frontend/public/onlyoffice/LICENSE.md](frontend/public/onlyoffice/LICENSE.md)
- Architecture + footguns: [docs/superpowers/specs/2026-05-05-office-collab-design.md](docs/superpowers/specs/2026-05-05-office-collab-design.md)
- Architecture comparison vs CryptPad / Google Workspace: [docs/research/07-collab-architecture-comparison.md](docs/research/07-collab-architecture-comparison.md)

---

## API Reference

Full REST API reference: [docs/api.md](docs/api.md).

Interactive Swagger UI is served at `http://localhost/swagger/index.html` when the stack is running. Click **Authorize** and paste a Bearer token from `POST /api/auth/login` to test authenticated endpoints. See [docs/contributing.md](docs/contributing.md#swagger-ui) for how to regenerate the spec after changing an endpoint.

---

## Contributing

Local development setup, backend/frontend workflow, database migrations, and code conventions: [docs/contributing.md](docs/contributing.md).

---

## Acknowledgements

Kutup's design and several of its core technical choices are directly inspired by — and in places adapted from — the work of three projects:

- **[OnlyOffice](https://github.com/ONLYOFFICE)** — the AGPL `documenteditor` / `spreadsheeteditor` / `presentationeditor` builds power kutup's collaborative `.docx` / `.xlsx` / `.pptx` editing. The bridged iframe + `x2t` WASM converter approach is taken straight from upstream OnlyOffice.
- **[CryptPad](https://github.com/cryptpad/cryptpad)** — the pattern of running OnlyOffice **client-only**, with all document state encrypted in the browser and never decrypted server-side, comes from CryptPad. kutup's `OnlyOffice / saveChanges → AEAD-wrapped frame → WebSocket relay` collab flow follows the same playbook (see `frontend/public/onlyoffice/` and [docs/superpowers/specs/2026-05-05-office-collab-design.md](docs/superpowers/specs/2026-05-05-office-collab-design.md)).
- **[Ente](https://github.com/ente-io/ente)** — kutup's E2EE primitives (libsodium-wrappers-sumo, the master-key / per-collection-key / per-file-key hierarchy, Argon2id-derived login keys, the streaming `crypto_secretstream_xchacha20poly1305` chunk format for file content) are modeled on Ente's open-source clients.

Where code, schemas, or protocol details were copied or closely adapted, the relevant files carry the upstream license headers — `AGPL-3.0-or-later` for OnlyOffice-derived code in `frontend/public/onlyoffice/` and `frontend/src/components/editors/office/`. Kutup itself is **AGPL-3.0-only** — the OnlyOffice subtree's "or-later" stays as upstream provides it.

---

## License

**AGPL-3.0-only** — Copyright (c) 2026 Alperen Albayrak

Kutup is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License, version 3, as published by the Free Software Foundation. See [LICENSE](LICENSE) for the full text.
