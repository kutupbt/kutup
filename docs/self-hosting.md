# Self-Hosting Guide

This guide covers a production Kutup deployment using Docker Compose.

---

## Prerequisites

- **Docker** 24+ and **Docker Compose** v2 (`docker compose` command, not `docker-compose`)
- A Linux server with at least 1 GB RAM
- A domain name (required for HTTPS and for federation to work correctly)

---

## Step 1: Clone and Configure

```sh
git clone https://github.com/kutupbulut/kutup.git
cd kutup
cp .env.example .env
```

Edit `.env` and fill in every value:

```sh
# PostgreSQL — use a strong random password
POSTGRES_PASSWORD=<strong-random-password>

# JWT secret — generate with:
#   openssl rand -hex 64
JWT_SECRET=<64-byte-hex-string>

# SeaweedFS S3 credentials — must match seaweedfs-s3.json
S3_ACCESS_KEY=kutup
S3_SECRET_KEY=<strong-random-secret>
S3_BUCKET=kutup-files

# Public URL — published as the federation API base
# Must be the address users (and remote servers) reach this instance at
SERVER_URL=https://kutup.example.com

# Unified federation v2 identity used by both Chat and Drive:
#   openssl rand -base64 32
# FEDERATION_SERVER_NAME=kutup.example.com
# FEDERATION_SIGNING_KEY=<base64-32-byte-ed25519-seed>

# Active Chat installations per account. V1 permits 1..=10.
CHAT_MAX_ACTIVE_DEVICES=10
CHAT_MEDIA_MAX_PLAINTEXT_BYTES=2147483648

# Optional contacts-only sealed sender. The policy contains public offline roots
# and root-signed online certificates; the normal server receives only the
# active online private key.
# CHAT_SEALED_SENDER_POLICY=<canonical one-line JSON>
# CHAT_SEALED_SENDER_ONLINE_PRIVATE_KEY=<base64-32-byte-libsignal-private-key>

# Break-glass admin bootstrap: a single email:username:password triple.
# Created on first start; the admin completes setup on first login.
# This account is the protected break-glass admin — it can never be
# demoted, disabled, or deleted. Promote further admins inside the app.
ADMIN_ACCOUNT=admin@example.com:admin:<strong-admin-password>

# SeaweedFS master — the admin dashboard probes it for real storage
# capacity + usage. Default works for the bundled compose.
SEAWEEDFS_MASTER_URL=http://seaweedfs-master:9333

# Optional fallback storage capacity (bytes) for the admin UI, used only
# when the SeaweedFS probe is unavailable. Unset / 0 hides the readout.
# STORAGE_TOTAL_BYTES=536870912000

# Days a trashed file/folder stays restorable before the hourly sweeper
# purges it permanently. 0 disables the automatic purge (trash only
# empties when users do it themselves). Default: 30.
# TRASH_RETENTION_DAYS=30

# Chat mailbox, temporary media-delivery, send-id retention, and inactive-device
# expiry. The hourly maintenance job enforces these; 0 disables an individual policy.
# CHAT_MAILBOX_RETENTION_DAYS=30
# CHAT_SEND_RETENTION_DAYS=30
# CHAT_MEDIA_DELIVERY_RETENTION_DAYS=45
# CHAT_DEVICE_EXPIRY_DAYS=90

# Rate limits (defaults shown). Most are per client IP; chat key fetches use a
# primary per-account budget plus a coarse IP outer wall. The backend resolves the
# client IP from the proxy-set X-Real-IP header, so keep the backend
# unreachable except through nginx.
# RATE_LIMIT_LOGIN_PER_MIN=10
# RATE_LIMIT_PREFLIGHT_PER_MIN=20
# RATE_LIMIT_REGISTER_PER_HOUR=10
# RATE_LIMIT_RECOVERY_PER_HOUR=5
# RATE_LIMIT_FED_USERS_PER_MIN=60
# RATE_LIMIT_ADMIN_PER_MIN=120
# RATE_LIMIT_CHAT_KEYS_PER_MIN=30
# RATE_LIMIT_CHAT_KEYS_IP_PER_MIN=120

# Optional OTLP/gRPC traces and metrics. Leave all endpoints unset for
# logs-only operation. Configure one shared endpoint, or both signal-specific
# endpoints; a partial exporter configuration fails startup.
# OTEL_EXPORTER_OTLP_ENDPOINT=https://collector.example.com:4317
# OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://collector.example.com:4317
# OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=https://collector.example.com:4317
# OTEL_SERVICE_NAME=kutup-server

# Per-account login lockout: this many failed password attempts lock the
# email out for the cooldown. Locked attempts return 429; the lock clears
# on its own. Defaults shown.
# LOGIN_LOCKOUT_THRESHOLD=5
# LOGIN_LOCKOUT_MINUTES=15
```

`CHAT_MAILBOX_RETENTION_DAYS` and `CHAT_MEDIA_DELIVERY_RETENTION_DAYS` are startup
fallbacks. An administrator can change both at runtime under **Admin → Settings →
Chat storage**; persisted values take precedence without a server restart.
Mailbox retention covers unread Direct and MLS delivery ciphertext. Media retention
covers only temporary delivery copies and never deletes protected history-media
copies.

### OpenTelemetry

The backend can export security-path traces and metrics to an OTLP/gRPC
collector. Set `OTEL_EXPORTER_OTLP_ENDPOINT` for a shared collector endpoint,
or set both `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` and
`OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`. If no endpoint is set, the server keeps
normal structured logs without installing an exporter. Once export is
configured, an incomplete or invalid exporter setup is a startup error rather
than a silent fallback.

The Chat security instruments cover authenticated policy lifecycle, monitor
freshness, proof sizes and outcomes, certificate issuance, sealed-send
outcomes, and limiter rejection. Their
attributes are bounded outcome or feature classes; usernames, account/device
identifiers, send IDs, capabilities and hashes, certificates, ciphertext, and
sender-recipient correlations are never metric labels or trace fields.

---

## Step 2: Configure SeaweedFS S3 Credentials

`seaweedfs-s3.json` must use the **same** access key and secret you set in `.env`:

```json
{
  "identities": [
    {
      "name": "kutup",
      "credentials": [
        {
          "accessKey": "kutup",
          "secretKey": "<same-S3_SECRET_KEY-as-in-.env>"
        }
      ],
      "actions": ["Admin", "Read", "Write"]
    }
  ]
}
```

The file is volume-mounted into the SeaweedFS S3 container at startup.

---

## Step 3: Start the Stack

```sh
docker compose up -d --build
```

This builds the backend and frontend images, then starts all services:

| Service | Role |
|---------|------|
| `postgres` | Database |
| `seaweedfs-master` | SeaweedFS master node |
| `seaweedfs-volume` | SeaweedFS volume server |
| `seaweedfs-filer` | SeaweedFS filer |
| `seaweedfs-s3` | SeaweedFS S3 gateway |
| `seaweedfs-init` | One-shot: creates the S3 bucket |
| `backend` | Rust API server (Axum, internal port 3000) |
| `frontend` | Compiled React app (served by Nginx) |
| `nginx` | Reverse proxy — listens on port 80; 443 requires the manual TLS setup below |

---

## Step 4: First Login

Find the admin password confirmation in the backend logs:

```sh
docker compose logs backend | grep -i "admin\|bootstrap"
```

Open `http://localhost` (or your domain) and log in. You will be redirected to a first-login setup page where you must:

1. Generate your **recovery phrase** (BIP39 mnemonic) — write it down and store it safely.
2. Optionally configure 2FA.

The recovery phrase is the only way to recover your account if you forget your password. It is never sent to the server.

---

## TLS / HTTPS

The bundled `nginx/nginx.conf` listens on port 80 only. To add HTTPS, add a second server block to `nginx/nginx.conf`:

```nginx
server {
    listen 443 ssl;
    server_name kutup.example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    # copy all location blocks from the port-80 server block here
}
```

Place your certificate files in `./nginx/certs/` (volume-mounted into the container):

```
nginx/certs/
├── fullchain.pem    # Certificate chain
└── privkey.pem      # Private key
```

Then reload Nginx:

```sh
docker compose exec nginx nginx -s reload
```

### Using Certbot (Let's Encrypt)

```sh
# On the host (not inside Docker)
certbot certonly --standalone -d kutup.example.com

# Copy into nginx/certs/
cp /etc/letsencrypt/live/kutup.example.com/fullchain.pem nginx/certs/
cp /etc/letsencrypt/live/kutup.example.com/privkey.pem nginx/certs/
```

---

## SERVER_URL

`SERVER_URL` must be set to the externally reachable base URL of your instance, including the scheme:

```
SERVER_URL=https://kutup.example.com
```

When chat federation is configured, this value is published as the delegated
`apiBase`. If it is wrong, cross-server sharing and chat routing will not work.

The unified v2 stack uses `FEDERATION_SERVER_NAME` and
`FEDERATION_SIGNING_KEY`. The name is the stable suffix in
`username@server`; no alias namespace is created. The stack persists a
self-signed genesis document and refuses startup if the configured seed is
silently changed. Account manifests are signed by clients and need no separate
server transparency seed. Production
federation requires public HTTPS and rejects loopback, private, link-local, and
other non-public resolved addresses; redirects are disabled.

To rotate the federation identity, keep the current seed in
`FEDERATION_SIGNING_KEY`, set a distinct `FEDERATION_NEXT_SIGNING_KEY`, stop
other replicas, and run:

```sh
docker compose run --rm backend federation-identity rotate
```

The command verifies and dual-signs one transition and is safe to retry. Then
move the new seed into `FEDERATION_SIGNING_KEY`, remove
`FEDERATION_NEXT_SIGNING_KEY`, and restart every replica. Losing the current
seed does not authorize replacement; remote peers will quarantine a competing
history and require an explicitly confirmed break-glass re-pin.

Federation is unavailable until both generic identity variables are set. Back
up the signing seed: losing it does not authorize silent replacement, and
remote servers will quarantine a conflicting history.

After configuring the identity, manage the unified control plane in **Admin →
Settings → Federation**. It has an emergency global stop and a feature-scoped
mode (`disabled`, `allowlist`, `blocklist`, or `open`), minimum trust
(`tofu` or `verified`), and per-domain inbound/outbound action (`inherit`,
`allow`, or `block`) with an optional trust override. Fresh databases start in
`allowlist`. `disabled` hides discovery/capability advertisement as well as
denying both directions. Saved rules survive mode changes, and `open`
intentionally ignores their admission actions; trust requirements still apply.

Admission policy is applied before outbound discovery/queuing and inbound
origin discovery. Admitted peers must still pass discovery/history signatures,
pinned-identity trust, SSRF, request/response signatures, replay, body,
protocol, and rate-limit checks. First contact creates a TOFU pin only after
cryptographic verification. The admin UI shows full fingerprints for out-of-
band verification, discovery failures, rotations, and quarantine; break-glass
re-pin requires the old and new full fingerprints plus the exact domain and is
audited. A reverse-proxy IP rule is not an equivalent domain-identity policy.

The same responsive panel shows per-peer Chat delivery and Drive share counts,
quarantined/failed filters, authenticated discovery timestamps, and the exact
preserved signed identity documents behind a pin or quarantine. “Retry visible”
re-resolves up to 100 filtered peers without treating one failure as a batch
failure. The federation-only audit feed can be filtered to one domain and
exported as spreadsheet-safe CSV; exported evidence contains public identity
material and operational errors, never the server signing seed or plaintext
Drive share capabilities.

After changing these values, rebuild the backend:

```sh
docker compose up -d --build backend
```

---

## Chat account manifests and device limit

V1 needs no transparency signing key, witness process, auditor service or
checkpoint monitor. Remove `CHAT_TRANSPARENCY_SIGNING_KEY` from deployment
configuration. Every account signs its own complete manifest locally; the
server verifies and distributes the current head and append-only history but
cannot mark a peer verified.

`CHAT_MAX_ACTIVE_DEVICES` defaults to 10 and accepts values from 1 through 10.
A lower value is a local resource/product policy. Ten is the V1 protocol hard
cap and cannot be raised by configuration:

```sh
CHAT_MAX_ACTIVE_DEVICES=10
CHAT_MEDIA_MAX_PLAINTEXT_BYTES=2147483648
```

`CHAT_MEDIA_MAX_PLAINTEXT_BYTES` is the per-attachment plaintext-class ceiling.
It defaults to the V1 hard cap of 2 GiB; an operator may lower it, but cannot
raise it without a future typed media-suite/protocol revision. Drive and Chat
media still share the account's one total quota—this is an individual-object
admission limit, not a reserved Chat storage budget.

First contact shows a gray shield. Users who require independent identity
authentication meet face to face and scan the conversation safety QR; an exact
match produces a green shield on that installation. A rollback, equivocation
or signed account-incarnation replacement produces a red quarantine and blocks
new sends. A healthy server response cannot clear it. For a legitimate
destructive account reset, the user scans the replacement QR; the client keeps
the old signed incarnation history and atomically promotes the new one.

Back up account recovery material. Recovery with the original phrase restores
the same master key and account authority. Administrative wipe is termination,
not recovery: it creates a new authority and requires contacts to re-verify.

## Contacts-only sealed sender

Provision the trust root on a machine that is not the Kutup application server.
The image contains an offline helper; copying that binary to the offline system
does not require copying the server configuration or database:

```sh
kutup-sealed-sender-provision root-generate /secure/kutup-sealed-root.key

kutup-sealed-sender-provision server-issue \
  --domain kutup.example.com \
  --root-key /secure/kutup-sealed-root.key \
  --online-key /secure/kutup-sealed-online.key \
  --certificate-id 1001 \
  --activates-at <unix-seconds> \
  --expires-at <unix-seconds> > sealed-policy.json
```

Both secret files are created once with mode `0600`; the helper refuses to
overwrite them or read an overly permissive root file. Keep the root offline.
Install the canonical policy JSON as `CHAT_SEALED_SENDER_POLICY` and the exact
contents of `kutup-sealed-online.key` as
`CHAT_SEALED_SENDER_ONLINE_PRIVATE_KEY`. The server validates the root chain,
certificate window, online public/private match, suite, and domain at startup.
It advertises sealed sender only after the signed service policy is durable:

```sh
docker compose run --rm backend feature-policy rotate sealed-sender
```

The first deployment bootstraps sequence 1 automatically; the explicit command
is required whenever persisted policy and configured policy differ. For root
rotation, first publish both roots, activate a new root-signed online
certificate, wait at least 24 hours plus the configured clock skew, then remove
the old root in another policy sequence. Never delete an active old root in the
same policy that introduces its replacement.

Sealed delivery is contacts-only. The 16-byte delivery capability is derived
from the recipient profile key and only its SHA-256 verifier is stored. Blocking
publishes a new profile key/verifier before redistributing that key to remaining
contacts. Anonymous prekey and send routes accept neither cookies nor bearer
tokens; destination mailboxes and federation transactions contain no sender
account/device. First-contact requests, Note to Self, and linked-device sync
remain identified, and an established sealed conversation never silently falls
back to identified delivery.

---

## Storage and Backups

All persistent data lives in Docker volumes and bind-mounted directories:

| Data | Location |
|------|----------|
| PostgreSQL database | `postgres_data` (Docker named volume) |
| SeaweedFS master metadata | `./data/seaweedfs-master` |
| SeaweedFS file chunks | `./data/seaweedfs-volume` |

**To back up:**

```sh
# PostgreSQL
docker compose exec postgres pg_dump -U "${POSTGRES_USER:-kutup}" "${POSTGRES_DB:-kutup}" | gzip > backup-$(date +%F).sql.gz

# SeaweedFS data
tar -czf seaweedfs-$(date +%F).tar.gz data/
```

Store backups off-site. The SeaweedFS data directories contain ciphertext only — even a full backup is useless without user keys.

---

## Updating

```sh
git pull
docker compose up -d --build
```

Database migrations run automatically on backend startup.

---

## Running Behind an Existing Reverse Proxy

If you already have Nginx or Caddy on the host, set the stack to not bind port 80 directly. Edit `docker-compose.yml` to change the nginx ports:

```yaml
nginx:
  ports:
    - "127.0.0.1:8080:80"   # bind only locally
```

Then proxy from your host Nginx to `http://127.0.0.1:8080`:

```nginx
server {
    listen 443 ssl;
    server_name kutup.example.com;

    ssl_certificate     /etc/letsencrypt/live/kutup.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/kutup.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        # Required for large file uploads:
        client_max_body_size 0;
        proxy_request_buffering off;
    }
}
```

For **Caddy**:

```
kutup.example.com {
    reverse_proxy localhost:8080
}
```

### Browser WASM cache policy

Kutup's generated `/chat-wasm/` and `/crypto-wasm/` JavaScript glue and WASM
binaries use stable filenames and form one deployment unit with the web bundle
and API server. They must be revalidated and must never receive an immutable
cache policy from an outer reverse proxy or CDN. The bundled frontend sends
`Cache-Control: no-cache, must-revalidate` for both paths. Preserve that header
when adding a cache layer. Normal Vite `/assets/` filenames are content-hashed
and may remain immutable.

Serving stale generated WASM with a newer JavaScript bundle can produce a
fail-closed Chat or Drive initialization error because the Rust and HTTP DTOs
no longer agree. Deploy the frontend, its generated WASM directories, and the
backend from the same release.

---

## Security Hardening

- **Change all defaults** in `.env` before first start. The defaults are intentionally weak placeholders.
- **Firewall:** Only expose ports 80 and 443. All other services (PostgreSQL, SeaweedFS) must not be reachable from the internet.
- **JWT_SECRET:** Use `openssl rand -hex 64`. A weak secret allows forging authentication tokens.
- **ADMIN_ACCOUNT:** Keep this set — it defines the protected break-glass admin (never demotable/deletable). Rotate its password after first login, but don't remove the variable, or the break-glass protection lapses.
- **Quotas:** Set default storage quotas in the admin dashboard to prevent abuse.
- **Updates:** Keep Docker images and the application updated.

---

## SeaweedFS Bucket Versioning (required for collaborative editing)

The collaborative-edit feature uses S3 object versioning to store file snapshots. The `seaweedfs-init` Compose service enables versioning and applies a lifecycle policy automatically on stack startup.

The compose stack has been updated to:
1. Mount `seaweedfs-init.sh` and `lifecycle.json` into the init container.
2. The script waits for SeaweedFS S3, creates the bucket (idempotent), enables versioning, applies the lifecycle.

**Lifecycle defaults:** 30-day or 50-version retention for noncurrent versions, whichever yields more. Named (`keep_forever=true`) versions are kept indefinitely (the kutup backend's cleanup job filters them out — they don't rely on the SeaweedFS lifecycle alone).

To customize retention, edit `lifecycle.json` and re-run the init container:
```sh
docker compose run --rm seaweedfs-init
```

If you migrate an existing pre-collab-edit deployment, run `seaweedfs-init.sh` once after upgrading. The script is idempotent.
