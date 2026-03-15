# Kutup

> Self-hosted, end-to-end encrypted file storage with federation

![Go](https://img.shields.io/badge/Go-1.22-00ADD8?logo=go)
![TypeScript](https://img.shields.io/badge/TypeScript-5.4-3178C6?logo=typescript)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)
![License](https://img.shields.io/badge/License-MIT-green)

Kutup (also known internally as "Depo") is a privacy-first file storage platform where the server never sees your data. All encryption and decryption happens in the browser using [libsodium](https://libsodium.org/). You own your keys; the server stores only ciphertext.

---

## Features

- **End-to-end encryption** — files and metadata encrypted client-side with libsodium before upload; server stores only ciphertext
- **Folder hierarchy** — nested collections with arbitrary depth
- **Folder color coding** — visual organization for collections
- **Public share links** — token-based, no account needed for recipients
- **Collection sharing** — share folders with other users; per-user permissions (read / upload / delete)
- **Cross-server federation** — share collections with users on other Kutup instances
- **Two-factor authentication** — TOTP (compatible with any authenticator app)
- **Account recovery** — BIP39 mnemonic seed phrase or recovery key encrypts master key; no plaintext ever sent to server
- **Admin dashboard** — user management, storage statistics, global settings
- **Zero-knowledge server** — server never sees plaintext keys, filenames, or file contents
- **Storage quotas** — per-user storage limits configurable by admins

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Go 1.22, [Fiber v2](https://gofiber.io/), PostgreSQL 16 |
| Frontend | React 18, TypeScript 5.4, libsodium-wrappers-sumo, Redux Toolkit |
| Storage | SeaweedFS (S3-compatible) |
| Infrastructure | Docker Compose, Nginx |

---

## Quick Start

**Requirements:** Docker and Docker Compose v2.

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
| `POSTGRES_DB` | PostgreSQL database name | `depo` | No |
| `POSTGRES_USER` | PostgreSQL username | `depo` | No |
| `POSTGRES_PASSWORD` | PostgreSQL password | — | **Yes** |
| `JWT_SECRET` | Secret for signing JWTs. Generate with `openssl rand -hex 64` | — | **Yes** |
| `S3_ACCESS_KEY` | SeaweedFS S3 access key | `depo` | No |
| `S3_SECRET_KEY` | SeaweedFS S3 secret key | — | **Yes** |
| `S3_BUCKET` | S3 bucket name | `depo-files` | No |
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
                    per-collection key (random, NaCl secretbox)
                                  ↓ (encrypts)
                         per-file key (random) → encrypted file content
```

For collection sharing, a NaCl box keypair is generated per user. The sharer encrypts the collection key to the recipient's public key.

See [docs/architecture.md](docs/architecture.md) for the full design including the login flow, federation model, and storage layer.

---

## Self-Hosting Guide

For production deployment with TLS, reverse proxies, and backup strategies, see [docs/self-hosting.md](docs/self-hosting.md).

---

## API Reference

Full REST API reference: [docs/api.md](docs/api.md).

Interactive Swagger UI is served at `http://localhost/swagger/index.html` when the stack is running. Click **Authorize** and paste a Bearer token from `POST /api/auth/login` to test authenticated endpoints. See [docs/contributing.md](docs/contributing.md#swagger-ui) for how to regenerate the spec after changing an endpoint.

---

## Contributing

Local development setup, backend/frontend workflow, database migrations, and code conventions: [docs/contributing.md](docs/contributing.md).

---

## License

MIT — Copyright (c) 2026 Alperen Albayrak
