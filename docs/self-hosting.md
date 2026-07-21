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

# Required dedicated key-transparency operator identity. Generate a different
# seed once, back it up, and do not reuse the federation identity.
CHAT_TRANSPARENCY_SIGNING_KEY=<base64-32-byte-ed25519-seed>
# Optional independent witnesses (witness-id=base64-public-key) and threshold.
# CHAT_TRANSPARENCY_WITNESSES=audit.example=<base64-ed25519-public-key>
# CHAT_TRANSPARENCY_WITNESS_QUORUM=1

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

# Chat mailbox/send-id retention and inactive-device expiry. The hourly
# maintenance job enforces these; 0 disables an individual policy.
# CHAT_MAILBOX_RETENTION_DAYS=30
# CHAT_SEND_RETENTION_DAYS=30
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

# Per-account login lockout: this many failed password attempts lock the
# email out for the cooldown. Locked attempts return 429; the lock clears
# on its own. Defaults shown.
# LOGIN_LOCKOUT_THRESHOLD=5
# LOGIN_LOCKOUT_MINUTES=15
```

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
silently changed. Use a distinct random seed for key transparency. Production
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

## Chat key transparency and independent witnesses

Chat key transparency requires a persistent operator seed even when chat
federation is disabled:

```sh
openssl rand -base64 32
```

Store that output as `CHAT_TRANSPARENCY_SIGNING_KEY`, separately from the
federation key, and back it up. The database pins the derived public identity
and refuses a silent replacement; planned rotation will require an
authenticated transition rather than an environment-variable swap.

For split-view resistance, run `kutup-transparency-witness` under a different
administrative boundary with its own secret seed and persistent state volume.
The server Docker image includes this second binary. Derive the public values
that are safe to copy to the server:

```sh
KUTUP_WITNESS_SIGNING_KEY='<base64-32-byte-seed>' \
  kutup-transparency-witness --print-public-key
```

Configure the returned public key on the server as
`CHAT_TRANSPARENCY_WITNESSES=audit.example=<publicKey>` and set
`CHAT_TRANSPARENCY_WITNESS_QUORUM=1`. Obtain the operator key id/public key from
the server's public `/api/auth/settings` chat block, verify them through your
deployment channel, and configure the independent process with:

```text
KUTUP_WITNESS_TARGET=https://kutup.example.com/
KUTUP_WITNESS_ID=audit.example
KUTUP_WITNESS_SIGNING_KEY=<private witness seed; never copy to the server>
KUTUP_WITNESS_OPERATOR_KEY_ID=<pinned operator key id>
KUTUP_WITNESS_OPERATOR_PUBLIC_KEY=<pinned operator public key>
KUTUP_WITNESS_STATE_FILE=/state/checkpoint.json
KUTUP_WITNESS_INTERVAL_SECONDS=30
```

The witness requires HTTPS, refuses redirects, verifies append-only consistency
from its own state, submits its signature, and advances that state only after
the server accepts it. Keep `/state` durable and backed up. A nonzero client
quorum deliberately makes a newly published manifest temporarily unavailable
until enough witnesses have polled; clients fail closed and may retry after the
witness interval. The isolated reference topology and contract test are
`docker-compose.chat-transparency-witness.yml` and
`scripts/test-chat-transparency-witness.sh`.

The web client also monitors its homeserver checkpoint independently on chat
open, reconnect, foreground, restored connectivity, and every 15 minutes while
visible. Temporary network failure produces an availability warning and keeps
the last valid trust state. A cryptographic, consistency, rollback, policy, or
witness-quorum failure is persisted locally and blocks new sends until a later
valid checkpoint succeeds. Scheduled monitoring of remote federated
checkpoints is not implemented yet; it depends on authenticated remote
operator/witness policy distribution and rotation.

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
