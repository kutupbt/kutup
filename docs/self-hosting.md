# Self-Hosting Guide

This guide covers a production Kutup deployment using Docker Compose.

---

## Prerequisites

- **Docker** 24+ and **Docker Compose** v2 (`docker compose` command, not `docker-compose`)
- A Linux server with at least 1 GB RAM
- A domain name (required for HTTPS and for federation to work correctly)

The checked-in single-node Compose topology is convenient for evaluation, but
its SeaweedFS filer uses the upstream embedded LevelDB store inside the filer
container. Before treating it as production, move filer metadata to a durable
mounted directory or an external supported filer store and test a complete
restore. Until then, never remove/recreate that container without the
`/filerldb2` backup described below. SeaweedFS documents the embedded-store
default in its
[`filer` command source](https://github.com/seaweedfs/seaweedfs/blob/master/weed/command/filer.go).

---

## Step 1: Clone and Configure

```sh
git clone https://github.com/kutupbt/kutup.git
cd kutup
cp .env.example .env
```

Edit `.env` and fill in every value:

```sh
# PostgreSQL — names have checked-in defaults; use a strong password
POSTGRES_DB=kutup
POSTGRES_USER=kutup
POSTGRES_PASSWORD=<strong-random-password>

# JWT secret — generate with:
#   openssl rand -hex 64
JWT_SECRET=<64-byte-hex-string>

# Object storage credentials — the bundled SeaweedFS's by default, injected
# into every bundled service by Compose. For another S3 store see "Using
# another S3 store" below.
S3_ACCESS_KEY=kutup
S3_SECRET_KEY=<strong-random-secret>
S3_BUCKET=kutup-files
S3_REGION=us-east-1

# Public URL — published as the federation API base
# Must be the address users (and remote servers) reach this instance at
SERVER_URL=https://kutup.example.com

# Stable account-address suffix. Set it once before accounts are created.
# If federation is enabled, it must match FEDERATION_SERVER_NAME.
CHAT_SERVER_NAME=kutup.example.com

# Unified federation v2 identity used by both Chat and Drive. Optional: a
# server without it makes and keeps its own (see "SERVER_URL" below).
#   openssl rand -base64 32
# FEDERATION_SERVER_NAME=kutup.example.com
# FEDERATION_SIGNING_KEY=<base64-32-byte-ed25519-seed>
# FEDERATION_NEXT_SIGNING_KEY=<set only during authenticated key rotation>

# Active Chat installations per account. V1 permits 1..=10.
CHAT_MAX_ACTIVE_DEVICES=10
CHAT_MEDIA_MAX_PLAINTEXT_BYTES=2147483648

# Group chats and group calls. Set to false for direct chats only: the server
# then reports no groups and refuses the group routes, and the apps hide
# them. Groups made earlier stay stored but cannot be opened.
CHAT_GROUPS=true

# Link previews: the server fetches public https pages (port 443, public
# addresses only) for the sender's previews. It then sees the links its users
# preview, never their messages. Set to false to turn previews off.
CHAT_LINK_PREVIEWS=true

# Web Push: wake Chat devices whose browser is closed. Pushes are empty (the
# server cannot read messages); the server sends them only to the push
# services listed (exact hosts, or .suffix for subdomains). The VAPID key is
# made once and kept in the database. Subject: a mailto: or https: contact.
CHAT_WEB_PUSH=true
# CHAT_WEB_PUSH_HOSTS=fcm.googleapis.com,updates.push.services.mozilla.com,.push.apple.com,.notify.windows.com
# CHAT_WEB_PUSH_SUBJECT=mailto:admin@example.com

# Calls: media flows browser to browser (DTLS-SRTP). STUN finds public
# addresses; a TURN relay (coturn with use-auth-secret) carries calls that
# can't connect directly and hides addresses for "Always relay calls".
# The server hands out 12-hour credentials made with CHAT_TURN_SECRET.
# `docker compose --profile turn up` starts coturn with the same secret.
# CHAT_STUN_URLS=stun:turn.example.com:3478
# CHAT_TURN_URLS=turn:turn.example.com:3478?transport=udp,turn:turn.example.com:3478?transport=tcp
# CHAT_TURN_SECRET=<long random string>
# CHAT_TURN_REALM=turn.example.com

# Group calls: a LiveKit SFU (`docker compose --profile sfu up`). Browsers
# connect to CHAT_SFU_URL; the bundled nginx serves the SFU at
# wss://sfu.<domain>, which needs DNS and a place on the certificate. UDP
# 50000-60000 and TCP 7881 must be reachable. Frames are end-to-end
# encrypted, so the SFU forwards what it cannot read. Without these, accounts
# here can join group calls other servers host but not start one.
# CHAT_SFU_URL=wss://sfu.example.com
# CHAT_SFU_API_KEY=<key name>
# CHAT_SFU_API_SECRET=<32+ random characters>

# Optional contacts-only sealed sender. The policy contains public offline roots
# and root-signed online certificates; the normal server receives only the
# active online private key.
# CHAT_SEALED_SENDER_POLICY=<canonical one-line JSON>
# CHAT_SEALED_SENDER_ONLINE_PRIVATE_KEY=<base64-32-byte-libsignal-private-key>

# Private MLS groups work without configuration: the server orders them with
# a control key it makes and the standard v1 policy. Set both values only to
# publish a custom policy.
# CHAT_MLS_ORDERING_POLICY=<canonical authenticated policy JSON>
# CHAT_MLS_CONTROL_SIGNING_KEY=<base64 signing seed>

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
# RATE_LIMIT_FORK_PER_MIN=120           # each app opened redeems one session hand-off
# RATE_LIMIT_CALL_LINK_PER_MIN=60       # opening and joining a meeting link need no account
# RATE_LIMIT_USER_LOOKUP_PER_MIN=30
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

`.env.example` is the complete checked-in variable template. Keep
`CHAT_SERVER_NAME`, `FEDERATION_SERVER_NAME`, and the public host in
`SERVER_URL` aligned before creating accounts; changing an established account
address or federation identity is a protocol migration, not a DNS-only edit.

`CHAT_MAILBOX_RETENTION_DAYS` and `CHAT_MEDIA_DELIVERY_RETENTION_DAYS` are startup
fallbacks. An administrator can change both at runtime under **Admin → Settings →
Chat storage**; persisted values take precedence without a server restart.
Mailbox retention covers unread Direct and MLS delivery ciphertext. Media retention
covers only temporary delivery copies and never deletes protected history-media
copies.

Chat uses a dedicated quota, separate from Drive/general storage. It defaults
to 2 GiB for new accounts and covers message-history ciphertext, ordinary
delivery media, and protected history media. Change the default or an
individual account under **Admin → Settings → Chat storage**; persisted admin
settings take precedence without a restart. Lowering a quota below current use
preserves reads and blocks new charged work rather than evicting history.

The ordinary account UI reports storage as a read-only progress meter with
used and total values. It is not a quota-management control: only an authorized
administrator changes Drive or Chat quota policy from Admin settings.

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

## Step 2: Start the Stack

Compose injects `S3_ACCESS_KEY` and `S3_SECRET_KEY` from `.env` into SeaweedFS,
the bucket initializer, and the backend. No second credential file needs to be
edited or kept in sync.

The bundled Nginx already requires TLS. Before the first start, place a
certificate and key at `nginx/certs/fullchain.pem` and
`nginx/certs/privkey.pem`. For local evaluation only, generate a self-signed
localhost certificate:

```sh
mkdir -p nginx/certs
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout nginx/certs/privkey.pem -out nginx/certs/fullchain.pem \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1
```

Use the public-domain certificate procedure below for production. Then start
and wait for every health check:

```sh
docker compose up -d --build --wait
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
| `frontend` | The web apps — account, Drive, Chat, Photos, Maps and Office — and the OnlyOffice editor sandbox, each on its own hostname (Nginx) |
| `nginx` | TLS reverse proxy — host port 38080 redirects to HTTPS on 38443 by default |

**The web apps and their hostnames.** Each app has its own origin:
`account.`, `drive.`, `chat.`, `photos.`, `maps.` and `office.` under
`KUTUP_BASE_DOMAIN` (or the explicit
`KUTUP_{ACCOUNT,DRIVE,CHAT,PHOTOS,MAPS,OFFICE}_URL`). A seventh name,
`editor.` (`KUTUP_EDITOR_URL`), is not an app: it is the sandbox the
OnlyOffice editor runs in, which holds no session and no keys. The backend and the
`frontend` container read the same settings: the backend publishes the map to
the apps, and the `frontend` container serves one app per hostname (any other
hostname gets `404`) and sends the OnlyOffice sandbox's Content Security
Policy, which only Drive may embed. Point all seven names at the server, cover
them with the certificate, and keep the `Host` header when proxying; the
bundled `nginx` does.

---

## Step 3: First Login

Find the admin password confirmation in the backend logs:

```sh
docker compose logs backend | grep -i "admin\|bootstrap"
```

Open `https://localhost:38443` for the default local mapping (or your public
HTTPS domain) and log in. A self-signed local certificate produces a browser
warning. You will be redirected to a first-login setup page where you must:

1. Generate your **recovery phrase** (BIP39 mnemonic) — write it down and store it safely.
2. Optionally configure 2FA.

The recovery phrase is the only way to recover your account if you forget your password. It is never sent to the server.

---

## TLS / HTTPS

The checked-in Nginx configuration already redirects HTTP to HTTPS and serves
the application only from its TLS server block. Certificate files are mounted
read-only from:

```
nginx/certs/
├── fullchain.pem    # Certificate chain
└── privkey.pem      # Private key
```

Nginx cannot become healthy when either file is missing or invalid. After
renewing or replacing them, reload Nginx:

```sh
docker compose exec nginx nginx -s reload
```

### Automatic certificates

`docker-compose.acme.yml` adds a small companion that gets a Let's Encrypt
certificate for the app hostnames, renews it, and has Nginx pick each new
one up without a restart. It needs:

- `KUTUP_BASE_DOMAIN` in `.env` (the certificate covers `account`, `drive`,
  `chat`, `photos`, `maps`, `office` and `editor` under it; `KUTUP_ACME_DOMAINS`, a
  comma-separated list, names other hostnames instead, and
  `KUTUP_ACME_EXTRA_DOMAINS` adds names beside them, such as the group-call
  SFU's `sfu.<domain>`);
- each of those hostnames pointing at this machine;
- ports 80 and 443 reachable from the internet. Let's Encrypt proves
  ownership by fetching a file over port 80, so no DNS credentials are kept
  on the server.

```sh
docker compose -f docker-compose.yml -f docker-compose.acme.yml up -d --wait
```

The overlay publishes Nginx on 80 and 443. On the very first start Nginx
serves a self-signed certificate for the few seconds until the real one
arrives. `KUTUP_ACME_EMAIL` (optional) is where Let's Encrypt sends expiry
warnings; `KUTUP_ACME_STAGING=1` gets untrusted test certificates for trying
a setup out. Follow it with `docker compose ... logs acme`; a failed check is
tried again every 15 minutes. The certificate and Let's Encrypt account live
in the `acme_state` volume and `nginx/certs/`.

### Using Certbot (Let's Encrypt) by hand

Obtain the initial certificate before starting the Compose Nginx, or stop it so
Certbot's standalone listener can own ports 80/443. Copy the live material into
the mounted directory, restrict the private key, then start/reload the stack:

```sh
# On the host (not inside Docker)
certbot certonly --standalone -d kutup.example.com

# Copy into nginx/certs/
mkdir -p nginx/certs
cp /etc/letsencrypt/live/kutup.example.com/fullchain.pem nginx/certs/
cp /etc/letsencrypt/live/kutup.example.com/privkey.pem nginx/certs/
chmod 600 nginx/certs/privkey.pem
docker compose up -d --build --wait
```

The Compose file uses development host ports `38080` and `38443`. A production
deployment can map `80:80` and `443:443`, or keep the loopback mappings and use
an existing edge proxy as described below.

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

Without these variables the server makes its own identity on first start:
it is named after `CHAT_SERVER_NAME`, anchored at `SERVER_URL` (which must be
canonical HTTPS in production), and its seed is kept in the database table
`server_generated_keys`, so database backups carry it. Chat groups need this
identity even when every member is local, because clients verify each
ordering server's signed policy history; it admits no other server by itself.
Once a server has an identity it never makes another: to manage the seed
yourself (for rotation, say), copy it into the environment unchanged,

```sh
docker compose exec -T postgres psql -U kutup -d kutup -Atc \
  "SELECT encode(private_key, 'base64') FROM server_generated_keys WHERE purpose = 'federation-identity'"
```

and set it as `FEDERATION_SIGNING_KEY` with `FEDERATION_SERVER_NAME` equal to
`CHAT_SERVER_NAME`. Back up the signing seed either way: losing it does not
authorize silent replacement, and remote servers will quarantine a conflicting
history.

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

Each browser profile, private window, or profile whose site storage was
cleared is a separate Chat installation. Users can rename an installation from
Messages to an account-private label such as “Work laptop”. The immutable
numeric ID from 1 through 10 remains visible as secondary protocol-routing
metadata. Renaming does not rotate device keys, change manifest membership,
replace Direct/MLS sessions, or migrate protected history.

`CHAT_MEDIA_MAX_PLAINTEXT_BYTES` is the per-attachment plaintext-class ceiling.
It defaults to the V1 hard cap of 2 GiB; an operator may lower it, but cannot
raise it without a future typed media-suite/protocol revision. This is an
individual-object admission limit. All Chat media is charged to the dedicated
Chat quota; it never consumes the Drive/general quota.

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

### Continuous Chat history and retention

After unified recovery setup, Chat automatically protects display history and
eligible media in an account-local E2EE backup. There is no backup-disable or
device-transfer fallback. A clean browser restores verified history from the
account homeserver, but creates fresh device, Direct, and MLS protocol state.
See [`chat-backup.md`](chat-backup.md) for the lifecycle and
[`chat-backup-security-threat-model.md`](chat-backup-security-threat-model.md)
for the trust boundary.

The hourly job applies 30-day mailbox retention and 45-day ordinary
delivery-media retention by default. Runtime admin settings can override both,
and zero disables that policy. Delivery-media cleanup never deletes separately
protected history media. Account deletion and administrator loss-recovery wipe
purge all backup rows, object prefixes, staging/reconciliation state, and
charged Chat bytes.

## Contacts-only sealed sender

Without this, people can still message each other, but attachments, stickers,
view-once media and voice notes work only in Note to Self and in groups: in a
direct chat they travel by sealed delivery, and the app hides those controls
on a server that does not offer it.

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
Install the canonical policy JSON as `CHAT_SEALED_SENDER_POLICY` (on one
line; in `.env`, inside single quotes) and the exact contents of
`kutup-sealed-online.key` as `CHAT_SEALED_SENDER_ONLINE_PRIVATE_KEY`. The
policy's domain is the server's name: `FEDERATION_SERVER_NAME`, or
`CHAT_SERVER_NAME` on a server that made its own identity. A server that
cannot accept the two settings refuses to start, so try them first with a
one-off container, which goes through the same start-up checks without
touching the running server:

```sh
docker compose run --rm backend storage-check
```
 The server validates the root chain,
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

The complete recovery set spans these locations in the checked-in topology:

| Data | Location |
|------|----------|
| PostgreSQL database | `postgres_data` (Docker named volume) |
| SeaweedFS master metadata | `./data/seaweedfs-master` |
| SeaweedFS file chunks | `./data/seaweedfs-volume` |
| SeaweedFS filer/S3 namespace metadata | `/filerldb2` inside the `seaweedfs-filer` container unless you configure a durable filer store |

PostgreSQL contains the object references and encrypted key envelopes while
SeaweedFS contains the corresponding ciphertext. Back them up as one recovery
set. The simplest consistent operator procedure is a short maintenance window:

```sh
# Stop new application writes, then dump PostgreSQL.
docker compose stop nginx backend
mkdir -p backups/current
docker compose exec postgres pg_dump -U "${POSTGRES_USER:-kutup}" "${POSTGRES_DB:-kutup}" | gzip > backups/current/postgres.sql.gz

# Quiesce SeaweedFS, copy its container-local filer metadata, then archive the
# bind-mounted master and volume state.
docker compose stop seaweedfs-s3 seaweedfs-filer seaweedfs-volume seaweedfs-master
docker compose cp seaweedfs-filer:/filerldb2 backups/current/filerldb2
tar -czf backups/current/seaweedfs-data.tar.gz data/

# Resume and wait for the complete stack.
docker compose up -d --wait
```

Store the PostgreSQL dump, filer metadata, and master/volume archive together
off-site and test restoration on an isolated host. They are one logical
recovery point; restoring only the volume chunks does not restore the S3
namespace. When using a mounted or external filer store, replace the
`docker compose cp` step with that store's consistent backup procedure.
SeaweedFS object payloads are ciphertext, but database and object metadata are
still operationally sensitive. Protected content remains undecryptable without
the users' account keys/recovery material; encryption is not a substitute for
durable operator backups.

---

## Database backups

`scripts/backup-postgres.sh` dumps the database, encrypts the dump on this
machine, and stores it in the object store Kutup already uses (`S3_*` in
`.env`), under `database-backups/`. It works with the bundled SeaweedFS and
with an external store; with an external store the backups survive the loss
of the server, which is the point.

Set a passphrase in `.env` and **keep a copy of it somewhere else**. Without
it the backups cannot be read, and it is lost with the server otherwise.

```
KUTUP_BACKUP_PASSPHRASE=<openssl rand -hex 32>
# KUTUP_BACKUP_KEEP_DAYS=30
# KUTUP_BACKUP_PREFIX=database-backups
```

```sh
scripts/backup-postgres.sh                      # back up, then prune
scripts/backup-postgres.sh --list               # what is stored
scripts/backup-postgres.sh --fetch <name> kutup.dump   # download and decrypt
```

Backups older than `KUTUP_BACKUP_KEEP_DAYS` are removed after each run; the
newest is never removed. To run it nightly with systemd, from the
deployment's directory (here `/opt/kutup`):

```ini
# /etc/systemd/system/kutup-backup.service
[Unit]
Description=Back up the Kutup database to object storage
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
WorkingDirectory=/opt/kutup
ExecStart=/opt/kutup/scripts/backup-postgres.sh

# /etc/systemd/system/kutup-backup.timer
[Unit]
Description=Nightly Kutup database backup

[Timer]
OnCalendar=*-*-* 02:30:00 UTC
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
systemctl daemon-reload && systemctl enable --now kutup-backup.timer
journalctl -u kutup-backup.service      # each run's result
```

To restore onto a fresh server: set up `.env` with the same store, the same
`JWT_SECRET` and server names, and the passphrase, then

```sh
docker compose up -d --wait postgres
scripts/backup-postgres.sh --fetch <name> kutup.dump
docker compose exec -T postgres pg_restore -U kutup -d kutup --clean --if-exists --no-owner < kutup.dump
docker compose up -d --wait
```

The dump holds accounts, key envelopes and object references; the files'
ciphertext stays in the object store. A restore therefore returns to the
moment of the dump: files deleted since then are listed but gone, and files
added since then are in the store but no longer listed (`kutup-server
orphan-sweep` finds those).

## Updating

```sh
git pull
docker compose up -d --build --wait
```

Database migrations run automatically on backend startup.

---

## Running Behind an Existing Reverse Proxy

If you already have Nginx or Caddy on the host, bind the bundled TLS proxy only
to loopback. The default development ports can be made explicit as:

```yaml
nginx:
  ports:
    - "127.0.0.1:38080:80"
    - "127.0.0.1:38443:443"
```

Then proxy from the public edge to the bundled HTTPS listener. Prefer trusting
the private upstream certificate; `proxy_ssl_verify off` is acceptable only for
this loopback hop:

```nginx
server {
    listen 443 ssl;
    server_name kutup.example.com;

    ssl_certificate     /etc/letsencrypt/live/kutup.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/kutup.example.com/privkey.pem;

    location / {
        proxy_pass https://127.0.0.1:38443;
        proxy_ssl_verify off;
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
    reverse_proxy https://127.0.0.1:38443 {
        transport http {
            tls_insecure_skip_verify
        }
    }
}
```

### Browser WASM cache policy

Kutup's generated `/chat-wasm/` and `/crypto-wasm/` JavaScript glue and WASM
binaries use stable filenames and form one deployment unit with the web bundle
and API server. They must be revalidated and must never receive an immutable
cache policy from an outer reverse proxy or CDN. The bundled frontend sends
`Cache-Control: no-cache` for both paths. Preserve that header
when adding a cache layer. Normal Vite `/assets/` filenames are content-hashed
and may remain immutable.

Serving stale generated WASM with a newer JavaScript bundle can produce a
fail-closed Chat or Drive initialization error because the Rust and HTTP DTOs
no longer agree. Deploy the frontend, its generated WASM directories, and the
backend from the same release.

---

## Maps

Kutup stores no map data. On the admin **Maps** page you choose the
providers people may use (OpenFreeMap and OpenStreetMap, which need no API
key, and optionally your own tile server), and whether map traffic goes
through this server: **off** (browsers load maps from the provider),
**each person chooses**, or **always**. Each person's maps stay off until
they turn them on in their account's Maps settings. Turn maps off entirely
for no third-party requests at all.

Through the relay, providers see the server instead of people's addresses.
The relay keeps one shared tile cache in `MAPS_CACHE_DIR` (the compose file
uses the `maps_cache` volume; without the variable it is a temporary
directory), sized on the Maps page. Keep the cache on when OpenStreetMap is
offered: its [tile usage policy](https://operations.osmfoundation.org/policies/tiles/)
does not allow fetching the same tiles repeatedly. If your own tile server
is only reachable from the Kutup server (e.g. on the Docker network), set
map traffic to **always**.

The Maps app (`KUTUP_MAPS_URL`, e.g. `maps.example.org`, served by the same
frontend image) keeps people's place lists. Each list is an encrypted Drive
file (`.kutupmap`) that counts against its owner's storage, so no separate
storage or service is needed. Lists work with maps turned off: places are
then added by city (searched on the device) or by coordinates.

The Photos app (`KUTUP_PHOTOS_URL`, e.g. `photos.example.org`, the same
frontend image) shows people's photos and videos by when and where they were
taken. Photos are ordinary Drive files in folders people choose (by default
a "Photos" folder in My files), so they share the Drive storage quota and
need nothing more on the server. Dates, places and the rest are read on the
device and sealed inside each file's encrypted metadata; the Places map
uses the map settings above.

---

## Security Hardening

- **Change all defaults** in `.env` before first start. The defaults are intentionally weak placeholders.
- **Firewall:** Only expose ports 80 and 443. All other services (PostgreSQL, SeaweedFS) must not be reachable from the internet.
- **JWT_SECRET:** Use `openssl rand -hex 64`. A weak secret allows forging authentication tokens.
- **ADMIN_ACCOUNT:** Keep this set — it defines the protected break-glass admin (never demotable/deletable). Rotate its password after first login, but don't remove the variable, or the break-glass protection lapses.
- **Quotas:** Set both Drive/general and dedicated Chat defaults in the admin dashboard to prevent abuse.
- **Updates:** Keep Docker images and the application updated.

---

## Running published images

Building Kutup compiles the Rust server and the browser WebAssembly, which
needs several GiB of memory. A small server can run images built on another
machine instead.

On the build machine, logged in to the registry (`docker login ghcr.io`):

```sh
scripts/publish-images.sh
```

It builds the server and web images from the current commit, refuses a
working tree with uncommitted changes, tags both with the commit, pushes
them, and prints two lines to put in the server's `.env`:

```
KUTUP_SERVER_IMAGE=ghcr.io/kutupbt/kutup-server:<commit>
KUTUP_WEB_IMAGE=ghcr.io/kutupbt/kutup-web:<commit>
```

`KUTUP_IMAGE_REGISTRY` changes where they go. On the server, add
`docker-compose.images.yml` to the compose files; nothing is built there:

```sh
docker compose -f docker-compose.yml -f docker-compose.images.yml pull
docker compose -f docker-compose.yml -f docker-compose.images.yml up -d --wait
```

To update, publish from the new commit, change the two lines in `.env`, and
run the same two commands. The server applies its database migrations when
it starts.

## Using another S3 store

Kutup's server needs only ordinary S3 requests: put, get, list, delete,
batch delete and multipart upload. It does not need bucket versioning,
lifecycle rules or presigned URLs, and browsers never talk to the store —
every byte goes through the backend, so the bucket should stay private (no
public access, no public custom domain). The bundled SeaweedFS is a default,
not a requirement.

Two differences between stores are handled by the server, so no client has
to know which one is behind it: resumable uploads are stored as equal-sized
parts (Cloudflare R2 refuses parts of different lengths), and objects are
deleted by version only where the store supports that. Checked with
`storage-check` against SeaweedFS and Cloudflare R2.

To run on a store you already have (Cloudflare R2, Backblaze B2, Hetzner
Object Storage, MinIO, AWS S3, …):

1. Create a private bucket and an access key that can read, write, list and
   delete in it.
2. In `.env`, set `S3_ENDPOINT` to the store's S3 API address and
   `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_BUCKET` and `S3_REGION` to its values
   (R2's region is `auto`). The server addresses the bucket path-style
   (`<endpoint>/<bucket>/<key>`).
3. Check the store once, before any data depends on it:
   ```sh
   docker compose -f docker-compose.yml -f docker-compose.external-s3.yml run --rm backend storage-check
   ```
   It runs every kind of request the server makes, under its own
   `kutup-storage-check/` prefix, removes what it wrote, and prints one line
   per check. It exits non-zero if the store cannot do something Kutup needs.
4. Start the stack with both files, which leaves the SeaweedFS services out:
   ```sh
   docker compose -f docker-compose.yml -f docker-compose.external-s3.yml up -d --build --wait
   ```

The admin page cannot ask such a store for its capacity; set
`STORAGE_TOTAL_BYTES` if you want a capacity readout. The SeaweedFS backup
steps above do not apply: the store's durability is the provider's, and the
PostgreSQL backup is still yours to take.

## SeaweedFS bucket versioning and lifecycle

Kutup does not depend on S3 object versioning: every file version is an
object of its own (`files/{id}/versions/{versionId}`), and version retention
is Kutup's job (`docs/plans/drive-versions-v2.md` — the last day whole, then
hourly for a week, then daily up to each account's setting, 7 days to 10
years). Deletes remove every stored version of an object, so they are final
whether or not the bucket is versioned.

The `seaweedfs-init` Compose service still creates the bucket and applies
`lifecycle.json`, now only a safety net: anything overwritten or deleted
outside Kutup's own deletes (noncurrent versions, expired delete markers)
goes after a day. Re-run it after upgrading:
```sh
docker compose run --rm seaweedfs-init
```

Versions stored by earlier builds as S3 object versions of
`files/{id}/snapshot` are moved onto their own keys automatically when the
server starts.
