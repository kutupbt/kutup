# Contributing

Contributions are welcome. This guide covers local development setup for both the backend and frontend.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Go | 1.22+ | https://go.dev/dl/ |
| Node.js | 20+ | https://nodejs.org/ |
| pnpm | 9+ | `npm install -g pnpm` |
| Docker + Compose v2 | latest | https://docs.docker.com/get-docker/ |

---

## Local Development Setup

### 1. Clone and configure

```sh
git clone https://github.com/alperen-albayrak/kutup.git
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

The backend is a Go 1.22 application in `backend/`.

### Running natively

```sh
cd backend

# Export env vars (or use a tool like direnv)
export DATABASE_URL="postgres://depo:<POSTGRES_PASSWORD>@localhost:5432/depo?sslmode=disable"
export JWT_SECRET="<your-jwt-secret>"
export S3_ENDPOINT="http://localhost:8333"
export S3_ACCESS_KEY="depo"
export S3_SECRET_KEY="<your-s3-secret>"
export S3_BUCKET="depo-files"
export S3_REGION="us-east-1"
export APP_ENV="development"

go run ./...
```

The backend starts on `http://localhost:3000`.

> You need to expose the SeaweedFS S3 port to the host. Add `ports: ["8333:8333"]` to the `seaweedfs-s3` service in `docker-compose.yml` temporarily for local dev.

### Database migrations

Migrations live in `backend/db/migrations/` and are applied automatically on startup using **golang-migrate**.

To add a new migration:

```sh
# Install migrate CLI (one-time)
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Create a new migration
migrate create -ext sql -dir backend/db/migrations -seq <migration_name>
```

This creates two files: `<N>_<name>.up.sql` and `<N>_<name>.down.sql`. Write the forward migration in `.up.sql` and the rollback in `.down.sql`.

### Swagger UI

The API spec is generated from `// @` annotations in the handler files using [swaggo/swag](https://github.com/swaggo/swag). The generated files live in `backend/docs/` and are committed to the repo.

**Viewing the UI locally**

Start the stack, then open:

```
http://localhost/swagger/index.html
```

To authenticate, click **Authorize** and paste a Bearer token (obtain one from `POST /api/auth/login`).

**Regenerating the spec after changing an endpoint**

```sh
# Install the swag CLI (one-time)
go install github.com/swaggo/swag/cmd/swag@v1.8.1

# Regenerate from the handler annotations
cd backend
swag init -g main.go
```

Commit the updated `backend/docs/` files alongside your handler changes. The Dockerfile also runs `swag init` during `docker build`, so the image always reflects the current annotations.

**Adding annotations to a new handler**

Place the comment block immediately above the `func` signature:

```go
// @Summary      Brief description shown in the UI
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      MyRequestType  true  "Description"
// @Success      200   {object}  MyResponseType
// @Failure      400   {object}  ErrorResponse
// @Router       /auth/my-endpoint [post]
func (h *AuthHandler) MyEndpoint(c *fiber.Ctx) error {
```

Define any new request/response types at package level in `backend/handlers/models.go` so swag can resolve them. Types defined inside function bodies are invisible to the generator.

### Running tests

```sh
cd backend
go test ./...
```

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
├── backend/
│   ├── main.go              # Server setup and route registration
│   ├── config/config.go     # Environment-based configuration
│   ├── db/
│   │   ├── db.go            # Connection pool, migration runner
│   │   └── migrations/      # SQL migration files
│   ├── handlers/            # HTTP handlers (one file per domain)
│   │   └── models.go        # Exported request/response types for Swagger
│   ├── docs/                # Generated OpenAPI spec (swag init output)
│   ├── middleware/          # JWT auth, admin check, rate limiting
│   ├── services/            # Business logic (S3, quotas, TOTP)
│   └── utils/               # JWT helpers, token gen, SSRF check
├── frontend/
│   ├── src/
│   │   ├── api/client.ts    # Axios instance with auth interceptors
│   │   ├── crypto/          # All libsodium wrappers (symmetric, asymmetric, KDF, mnemonic)
│   │   ├── pages/           # Route-level components
│   │   ├── store/           # Redux slices (auth state)
│   │   └── workers/         # Web Worker for Argon2id KDF
│   └── vite.config.ts       # Dev server proxy config
├── nginx/nginx.conf          # Production Nginx config
├── docs/                     # Documentation
└── docker-compose.yml
```

---

## Code Conventions

### Backend (Go)

- Follow standard Go project layout. No framework-specific patterns beyond Fiber handler signatures.
- Handler files are organized by domain (auth, collections, files, shares, federation, admin).
- Use `pgx/v5` directly for database queries — no ORM.
- All cryptographic operations are the client's responsibility; the backend must never attempt to decrypt anything.
- SSRF validation (`utils/ssrf.go`) must be applied to all user-supplied URLs before making outbound requests (federation).

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
