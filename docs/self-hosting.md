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

## Quick start

Five steps from a fresh server to the first sign-in. The settings follow the
layout Ente uses for its self-hosted server (a short example env with only
what must be set, every other setting documented with its default:
[`server/config/example.env`](https://github.com/ente-io/ente/blob/main/server/config/example.env)
and its [environment reference](https://ente.com/help/self-hosting/installation/env-var)).

1. **Get the code and the settings file.**

   ```sh
   git clone https://github.com/kutupbt/kutup.git
   cd kutup
   cp .env.example .env
   ```

2. **Fill in the REQUIRED block at the top of `.env`.** Each line says how to
   make its value:

   | Setting | What it is | Make it with |
   |---|---|---|
   | `KUTUP_BASE_DOMAIN` | Your domain; the apps live on `account.`, `drive.`, `chat.`, … under it | — |
   | `SERVER_URL` | This server's public HTTPS address | — |
   | `CHAT_SERVER_NAME` | The name after the `@` in every address; set once | — |
   | `POSTGRES_PASSWORD` | The database password | `openssl rand -hex 32` |
   | `JWT_SECRET` | Signs sessions | `openssl rand -hex 64` |
   | `OPAQUE_SETUP_KEYS` | The keys sign-in is sealed under; back it up apart from the database | `echo "1:$(openssl rand -base64 32)"` |
   | `S3_SECRET_KEY` | The bundled object store's secret | `openssl rand -hex 32` |
   | `MAIL_FORWARDING_KEYS` | Mail forwarding's keys; forwarding stays off until it's set; back it up apart from the database | `echo "1:$(openssl rand -base64 32)"` |
   | `ADMIN_ACCOUNT` | The break-glass administrator, `username:password` | — |

   Everything below that block is optional and shows its default. Check the
   file without starting anything:

   ```sh
   docker compose run --rm --no-deps backend check-config
   ```

3. **Point the names at the server.** Each app hostname (`account`, `drive`,
   `chat`, `photos`, `maps`, `office`, `contacts`, `mail`, `pass` and the
   `editor` sandbox, under `KUTUP_BASE_DOMAIN`) needs a DNS record for this
   machine.

4. **Pick the compose files for your setup** and start:

   | You want | Add | Also set in `.env` |
   |---|---|---|
   | The base: every app, the bundled database and object store | `docker-compose.yml` | — |
   | Certificates from Let's Encrypt, renewed by themselves (ports 80 and 443 open) | `docker-compose.acme.yml` | optional `KUTUP_ACME_*` |
   | Mail to and from outside | `docker-compose.mail.yml` | `MAIL_HOSTNAME`, `MAIL_INBOUND_TOKEN`, `STALWART_ADMIN_SECRET` |
   | Your own S3 store (R2, B2, Hetzner, MinIO, AWS) instead of the bundled one | `docker-compose.external-s3.yml` | `S3_ENDPOINT`, `S3_ACCESS_KEY`, `S3_BUCKET`, `S3_REGION` |
   | Images built elsewhere instead of building here | `docker-compose.images.yml` | `KUTUP_SERVER_IMAGE`, `KUTUP_WEB_IMAGE` |

   For example, the base with automatic certificates and mail:

   ```sh
   export COMPOSE_FILE=docker-compose.yml:docker-compose.acme.yml:docker-compose.mail.yml
   docker compose up -d --build --wait
   ```

   Without `docker-compose.acme.yml`, put your certificate and key at
   `nginx/certs/fullchain.pem` and `nginx/certs/privkey.pem` first ("TLS /
   HTTPS" below).

5. **Sign in** at `https://account.<KUTUP_BASE_DOMAIN>` with `ADMIN_ACCOUNT`
   and finish setup ("First login" below).

---

## Configuration reference

`.env.example` is the reference: every setting the server, the compose files
and the scripts read, each once, grouped by area (General, Automatic
certificates, Database and storage, Chat, Calls, Mail, Names and federation,
Rate limits and sign-in lockout, Monitoring, Published images, Advanced), with
its default and one line on what it does. A test
(`env_example_lists_every_setting_once` in `crates/kutup-server/src/config.rs`)
keeps it that way, and checks that the compose files pass each setting the
server reads on to it. The server checks every value at start: one it cannot
read (a number that is not one, an unknown choice, an unknown `RATE_LIMIT_*`
name) stops it with exit code 2 and the full list of problems, never a silent
default. `kutup-server check-config` runs that check alone (no database, no
migrations); run it against a new image and your `.env` before switching over.

**Chat groups are off by default** (`CHAT_GROUPS=false`): Chat offers direct
chats, calls and meeting links, but no group chats or group calls; the
server reports none and refuses the group routes. Groups return with the
pairwise group design that replaces them (docs/roadmap.md). `CHAT_GROUPS=true`
switches the current groups on, for testing only. Groups need federation
configured: a group's home answers only through the anonymous route, under
a weekly HPKE key derived from the federation identity. A home stores each
group's state and change log with members as per-group pseudonyms, never an
account; `CHAT_GROUP_MAX_MEMBERS` (1 to 256, default 256) caps a group's
members and open invitations, and `CHAT_GROUP_MAX_GROUPS` (default 100000)
the groups it hosts (new groups are also limited per relaying server). A
group's change log keeps only the changes a current member may still read:
those from the earliest revision any member joined at, plus the latest.

Keep `CHAT_SERVER_NAME`, `FEDERATION_SERVER_NAME`, and the public host in
`SERVER_URL` aligned before creating accounts; changing an established account
address or federation identity is a protocol migration, not a DNS-only edit.

`CHAT_MAILBOX_RETENTION_DAYS` and `CHAT_MEDIA_DELIVERY_RETENTION_DAYS` are startup
fallbacks. An administrator can change both at runtime under **Admin → Settings →
Chat storage**; persisted values take precedence without a server restart.
Mailbox retention covers unread Direct and MLS delivery ciphertext. Media retention
covers only temporary delivery copies and never deletes protected history-media
copies.

Each account has one storage pool. Drive, Photos, Office, Maps and Chat
(message-history ciphertext, ordinary delivery media, and protected history
media) all count against it. New accounts get the **Default storage quota
(GiB)** set under **Admin → Server settings** (10 GiB until changed); existing
accounts keep theirs. Change an individual account's **Storage quota (GiB)**
under **Admin → Users**. Lowering
a quota below current use preserves reads and blocks new charged work rather
than evicting files or history.

Users see their pool under **Account → Settings → Storage**: a ring of what
fills it, largest first (file types, trash, earlier versions, previews, Chat
attachments and history, uploads in progress), and **Free up space**, which
empties the trash, lists large files to move to trash, deletes earlier file
versions older than a chosen age and points to Chat's media clearing. The Drive, Photos and Office storage meters open a summary
that links there, as does Chat's storage screen. Only an administrator changes
a quota.

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

## The stack

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
| `frontend` | The web apps — account, Drive, Chat, Photos, Maps, Office, Contacts, Mail and Pass — and the OnlyOffice editor sandbox, each on its own hostname (Nginx) |
| `nginx` | TLS reverse proxy — host port 38080 redirects to HTTPS on 38443 by default |

**The web apps and their hostnames.** Each app has its own origin:
`account.`, `drive.`, `chat.`, `photos.`, `maps.`, `office.`, `contacts.`,
`mail.` and `pass.` under `KUTUP_BASE_DOMAIN` (or the explicit
`KUTUP_{ACCOUNT,DRIVE,CHAT,PHOTOS,MAPS,OFFICE,CONTACTS,MAIL,PASS}_URL`). One more name,
`editor.` (`KUTUP_EDITOR_URL`), is not an app: it is the sandbox the
OnlyOffice editor runs in, which holds no session and no keys. The backend and the
`frontend` container read the same settings: the backend publishes the map to
the apps, and the `frontend` container serves one app per hostname (any other
hostname gets `404`) and sends the OnlyOffice sandbox's Content Security
Policy, which only Drive may embed. Point all eight names at the server, cover
them with the certificate, and keep the `Host` header when proxying; the
bundled `nginx` does.

**Email addresses and their keys.** Every account with a username has the
address `username@<CHAT_SERVER_NAME>` and an OpenPGP key, created in the
browser after sign-in (Account → Settings → Encryption keys, where keys can
also be replaced by a new one, imported, exported locked with a passphrase,
and marked obsolete or compromised). Outside OpenPGP clients (GnuPG,
Thunderbird, Proton) find the key through Web Key Directory, in one of two
places:

- the direct method, `https://<CHAT_SERVER_NAME>/.well-known/openpgpkey/hu/…`:
  the server name must reach this server over HTTPS (or a proxy in front of
  it must pass `/.well-known/openpgpkey/` through, as for
  `/.well-known/kutup/`);
- the advanced method, `https://openpgpkey.<CHAT_SERVER_NAME>/.well-known/openpgpkey/<CHAT_SERVER_NAME>/hu/…`.
  Clients ask here first whenever the name resolves, and a wildcard DNS
  record makes it resolve. Then it must answer: point it at this server and
  add it to the certificate (`KUTUP_ACME_EXTRA_DOMAINS=openpgpkey.<domain>`).
  Without a wildcard and without this record, the direct method alone is
  used.

The bundled `nginx` routes `/.well-known/openpgpkey/` to the backend on every
hostname. Mail itself is set up in "Mail" below.

---

## First login

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

The server's own outbound HTTPS (federation with other Kutup servers, Web
Push, outside mail keys, maps and the rest) runs on rustls with aws-lc-rs and
offers the post-quantum hybrid key exchange X25519MLKEM768 first, falling back
to X25519 or the NIST curves for peers without it. Nothing needs configuring.
The bundled Nginx still accepts TLS 1.2 as well as 1.3 (`docs/roadmap.md`).

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
- ports 80 and 443 reachable from the internet, and UDP 443 for HTTP/3
  (optional: browsers fall back to TCP). Let's Encrypt proves ownership by
  fetching a file over port 80, so no DNS credentials are kept on the
  server.

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
individual-object admission limit. Chat media is charged to the account's one
storage pool, shared with Drive and the other apps.

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

Attachments, stickers, view-once media and voice notes in a direct chat travel
by sealed delivery; on a server that does not offer it they work only in Note
to Self and in groups.

Sealed delivery between accounts of the same server does not depend on
federation: turning federation off (Admin → Federation) stops other servers
from being reached, and leaves sealed delivery, and with it media in direct
chats, working on the server itself.

### Provisioned by the server (the default)

With neither `CHAT_SEALED_SENDER_*` setting, a server with a federation
identity (configured, or the one it makes for itself) offers sealed sender with
no setup:

- On first start it generates a root in memory, signs a 90-day online
  certificate with it, stores the root's public key, the certificate and the
  online private key (`sealed_sender_generated_certificates`), publishes the
  signed policy, and drops the root's private key. It is never written
  anywhere.
- 30 days before a certificate runs out it does the same with a new root. The
  new root and certificate are published at once and issue sender
  certificates from 24 hours and 5 minutes later, the same rule as for an
  offline root. The old certificate keeps issuing until then and leaves the
  policy when it expires; its online key is then wiped. Every instance checks
  hourly; a database lock makes them agree.
- A server that was down for most of a window renews at once rather than
  leaving a day in which nothing can issue.

What this gives up against an offline root is small. A copy of the database
holds the online key, which signs sender certificates until its certificate
expires, as the configured online key does; it cannot sign another server
certificate under that root. The policy itself is signed by the federation
identity key, which lives on the server in both modes, so whoever holds that
key could publish a root of their own either way. Sender certificates never
let anyone speak as an account: a recipient checks the identity key in each
one against the sender's signed device list, and the message inside is
authenticated by the device's own Signal identity.

### From an offline root

For an operator who wants the root kept off the server. Setting both values
replaces the server's own provisioning; a server that has published a policy
under an offline root does not switch back to its own by itself (start it
once with `feature-policy rotate sealed-sender` and the settings removed to do
so).

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
| Stalwart queue and DKIM keys (with Mail) | `stalwart_data` (Docker named volume) |

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

The database backups below do not hold `OPAQUE_SETUP_KEYS` (it is in `.env`),
and must not: back that key up on its own, somewhere else. A database restored
without it signs no one in (see the security notes).

The same goes for `MAIL_FORWARDING_KEYS`, when Mail's end-to-end forwarding
is on (docs/plans/mail-forwarding.md): the proxy factors in the database are
sealed under it, so a dump alone doesn't hold them. A database restored
without it keeps every message; its end-to-end forwardings stop (Outdated)
until their owners re-enable them. Mail keeps arriving either way.

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

Servers that federate Chat with each other update together when a federation
wire version changes. Sealed Chat federation moved to version 2 on 2026-10-18
(a device mismatch now closes its sequence): a server on version 2 and one on
version 1 refuse each other's sealed sends for good, and the client sees them
as refused. The version-2 server logs "sealed federation peer runs another
version" when it refuses a version-1 send, and "the recipient's server refused
a sealed send for good" (with the peer's error) when a version-1 server
refuses its own; the version-1 server logs only a generic invalid transaction.
Sealed sends between the two resume once both run the same version.

Each backend also holds up to `SEALED_FLUSH_LOCK_CONNECTIONS` (default 4)
Postgres sessions of its own beside its main pool: one per destination server
it is delivering sealed Chat to at that moment, holding a session advisory
lock so two backends never deliver to the same server at once. Count them in
Postgres's `max_connections`. Session advisory locks need a direct connection
or a session-mode pooler: behind PgBouncer in transaction mode they don't
hold.

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

### Browser cache policy

Every static file the apps load has a URL that changes when its content does,
so the bundled frontend caches them for good (`Cache-Control: public,
max-age=31536000, immutable`):

- Vite's `/assets/` bundles (content-hashed file names);
- the Rust/WASM runtimes under `/crypto-wasm/<hash>/` and `/chat-wasm/<hash>/`,
  directories named for the files' content hash, which the bundle names;
- the OnlyOffice client and x2t on the editor host under
  `/onlyoffice/dist/<version>/`, directories named for their versions.

The pages that name them (`index.html`, the editor's `inner.html` and
`x2t.html`) are `no-cache`. An outer cache or CDN may keep these policies as
they are; it must not cache the HTML pages longer.

Files are stored compressed at build time (gzip and brotli, served with
`Vary: Accept-Encoding`). A reverse proxy in front should pass
`Accept-Encoding` through and not recompress.

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

The Contacts app (`KUTUP_CONTACTS_URL`, e.g. `contacts.example.org`, the
same frontend image) is the account's address book. Names and email addresses
are readable by the server (for suggestions in pickers); every other detail is
end-to-end encrypted, and each contact's readable part is signed by the
account so the server cannot change it. Contacts count against the account's
storage. An existing deployment that names its apps one by one must add
`KUTUP_CONTACTS_URL` (or set `KUTUP_BASE_DOMAIN`), point `contacts.` at the
server and add it to the certificate; with `docker-compose.acme.yml` the name
is requested automatically.

Kutup Pass (`KUTUP_PASS_URL`, e.g. `pass.example.org`, the same frontend
image) is the password manager (`docs/plans/pass.md`). Its vaults are KeePass
files (`.kdbx`) in Drive, so they share the Drive storage quota, open in
KeePassXC through `kutup sync`, and need nothing more on the server than the
vault secrets it keeps sealed. An existing deployment that names its apps one
by one must add `KUTUP_PASS_URL` (or set `KUTUP_BASE_DOMAIN`), point `pass.`
at the server and add it to the certificate; with `docker-compose.acme.yml`
the name is requested automatically.

The Photos app (`KUTUP_PHOTOS_URL`, e.g. `photos.example.org`, the same
frontend image) shows people's photos and videos by when and where they were
taken. Photos are ordinary Drive files in folders people choose (by default
a "Photos" folder in My files), so they share the Drive storage quota and
need nothing more on the server. Dates, places and the rest are read on the
device and sealed inside each file's encrypted metadata; the Places map
uses the map settings above.

---

## Mail

The Mail app (`KUTUP_MAIL_URL`, e.g. `mail.example.org`, the same frontend
image) reads and writes mail in the browser: messages between Kutup users are
end-to-end encrypted, and the server stores every message encrypted to its
address key. A deployment that names its apps one by one must add
`KUTUP_MAIL_URL` (or set `KUTUP_BASE_DOMAIN`); with `docker-compose.acme.yml`
the name is on the certificate automatically. The same `mail.` name can serve
the web app (port 443) and Stalwart (port 25).

Kutup receives mail for `<username>@CHAT_SERVER_NAME` through
[Stalwart](https://stalw.art), which runs unmodified beside it
(`docker-compose.mail.yml`, `docs/plans/mail.md`). Stalwart answers on port
25, asks Kutup whether each recipient exists and has room, and hands accepted
mail to Kutup, which encrypts it to the address key before storing it. Mail
counts against the account's storage. An account can receive mail once it
has signed in to the Account app once, which creates its address key.

1. In `.env`, set `MAIL_HOSTNAME` (e.g. `mail.example.org`),
   `MAIL_INBOUND_TOKEN` and `STALWART_ADMIN_SECRET` (each
   `openssl rand -hex 32`). With `docker-compose.acme.yml`, add
   `MAIL_HOSTNAME` to `KUTUP_ACME_EXTRA_DOMAINS` so port 25 offers a trusted
   certificate. The backend gets `MAIL_HOSTNAME` too: it trusts DMARC only
   from the `Authentication-Results` header Stalwart writes under that name
   (people's allow lists rely on it). `stalwart-setup` turns Stalwart's
   `addAuthResultsHeader` on for port 25 and stops with a `FATAL` line if
   Stalwart reports it off. Kutup sends through Stalwart's submission port
   (2587), which is internal: only the backend reaches it, and Stalwart's
   inbound throttles skip it (Kutup limits each account's sending itself;
   port 25 keeps them). `stalwart-setup` stops with a `FATAL` line if a
   throttle still covers it. To let people forward their mail (Mail →
   Settings → Forwarding), also set `MAIL_FORWARDING_KEYS`
   (`echo "1:$(openssl rand -base64 32)"`); without it no forwarding can be
   set up.
2. Open TCP port 25 inbound and outbound. Many hosting providers block
   outbound port 25 until asked; mail to people outside Kutup needs it.
3. Start with the mail file added:
   `docker compose -f docker-compose.yml -f docker-compose.acme.yml -f docker-compose.mail.yml up -d --wait`.
   The `stalwart-setup` service applies Kutup's settings to Stalwart
   (`stalwart/plan.ndjson`) on every start and reloads its certificate daily.
   Stalwart's own management port is never published.
4. DNS, for the domain after the `@` (`example.org`) unless noted:

   | Record | Value |
   |---|---|
   | `mail.example.org` A | the server's IPv4 address; its PTR (set at the hosting provider) must be `mail.example.org` |
   | SPF: TXT on `example.org` | `v=spf1 ip4:<the IPv4 address> -all` |
   | DKIM: TXT records | the ones Stalwart generated: `docker compose exec stalwart-setup stalwart-cli get Domain <id>` shows its `dnsZoneFile` (find the id with `stalwart-cli query Domain`) |
   | DMARC: TXT on `_dmarc.example.org` | `v=DMARC1; p=none; rua=mailto:postmaster@example.org`, tightened to `quarantine` and `reject` once reports look clean |
   | MX on `example.org` | `10 mail.example.org`, **last**, once everything above is in place |

   Stalwart sends over IPv4 only, so no IPv6 PTR is needed.

**Sending safety.** One account sending spam can get the server's address
blocklisted, and then nobody's mail arrives. Kutup limits mail to outside
addresses per account (100 recipients an hour and 500 a day, and 50 a day in
an account's first week: `MAIL_SEND_RECIPIENTS_PER_HOUR`, `…_PER_DAY`,
`MAIL_NEW_ACCOUNT_RECIPIENTS_PER_DAY`, `MAIL_NEW_ACCOUNT_DAYS`), pauses an
account whose mail bounces too often, and shows who sends how much under
Administration → Mail sending, where an account can be paused, resumed or
given its own limits. `postmaster@`, `abuse@`, `security@` and `hostmaster@`
are groups: add the people who read them under Administration → Mail
groups; until then they reach every administrator. Read them.
`/.well-known/security.txt` names `security@`. Before the MX switch, register the domain with
[Google Postmaster Tools](https://postmaster.google.com) and
[Microsoft SNDS](https://sendersupport.olc.protection.outlook.com/snds/) so
complaints and reputation reach you. Stalwart's spam filter does not score
outgoing mail: its rules judge the connection more than the content, and
refused ordinary mail in tests.

**Sending outside.** Administration → Mail sending decides who may send to
addresses outside Kutup: nobody (`off`; Mail offers only Kutup addresses),
administrators only (`admins`, for a sending trial from the real Mail app) or
everyone (`on`). A change applies at once, without a restart, and is recorded
in the activity log. `MAIL_OUTSIDE_SENDING` (default `off`) only gives the
first value, when the server starts without one stored; after that the
administrators' choice wins, and changing the variable does nothing. Keep it
off until SPF, DKIM, DMARC and the PTR are in place; receivers judge a new
address by its first messages. Mail between Kutup users always goes.

**Checking a domain.** `scripts/check-mail-ready.sh example.org
--dkim-selector <selector> --address you@example.org` prints one line per
check (A, PTR, MX, SPF, DKIM, DMARC, port 25 with STARTTLS and its
certificate, both WKD methods) and fails when one does. Run it from a machine
outside the server, before the MX switch and after (`--after` then makes a
wrong MX fail). Many networks block outbound port 25; the script says so
instead of failing, and receiving a message from Gmail checks that part.

**Mail backups.** Stalwart's `stalwart_data` volume holds its DKIM private
keys and the mail it has not handed over yet; losing it means publishing new
DKIM records. `scripts/backup-stalwart.sh` stores it encrypted beside the
database backups (same `.env` settings and passphrase, under `mail-backups/`,
`KUTUP_MAIL_BACKUP_PREFIX` to change), stopping Stalwart for the seconds the
copy takes (senders retry). Run it nightly like the database backup:

```ini
# /etc/systemd/system/kutup-mail-backup.service
[Unit]
Description=Back up Kutup's Stalwart data to object storage
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
WorkingDirectory=/opt/kutup
ExecStart=/opt/kutup/scripts/backup-stalwart.sh

# /etc/systemd/system/kutup-mail-backup.timer
[Unit]
Description=Nightly backup of Kutup's Stalwart data

[Timer]
OnCalendar=*-*-* 03:00:00 UTC
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
systemctl daemon-reload && systemctl enable --now kutup-mail-backup.timer
systemctl status kutup-mail-backup.service   # a failed run shows as failed
```

To restore: `scripts/backup-stalwart.sh --list`, then `--fetch <name>
stalwart.tar.gz` and `--restore stalwart.tar.gz` (it stops Stalwart, replaces
the volume's contents, and starts it again).

**Moving MX to Kutup.** Mail starts arriving at Kutup only when the domain's MX
record points at it, so this is the last step, done once the rest works.
Mail between Kutup users and mail Kutup sends out work before it; inbound
mail from outside does not. `scripts/check-mail-ready.sh` covers most of the
list. Check, in order:

1. `mail.example.org` resolves to the server's IPv4 address and its PTR is
   `mail.example.org` (`dig +short -x <address>`).
2. SPF, DKIM and DMARC are published (the table above), and any SPF include
   left by an earlier mail service is gone: Cloudflare Email Routing adds
   `include:_spf.mx.cloudflare.net`, so replace the record with Kutup's.
3. Port 25 answers from outside with a trusted certificate:
   `openssl s_client -starttls smtp -connect mail.example.org:25 -servername mail.example.org`.
4. WKD answers in both places above (`curl -sS -o /dev/null -w '%{http_code}'`
   on each `policy` URL gives `200`), so OpenPGP users write to Kutup users
   encrypted from the first message.
5. Every person who should receive mail has signed in once (that creates
   their key; mail to an account without one is refused), and
   `postmaster@` and `abuse@` reach people who read them (their groups'
   members, or every administrator).
6. The domain is registered with Google Postmaster Tools and Microsoft
   SNDS.
7. A sending trial: Administration → Mail sending set to "Administrators
   only", then an administrator sends from Mail to Gmail, Outlook and Proton
   addresses and checks each arrives in the inbox with SPF, DKIM and DMARC
   passing (Gmail's "Show original"). Then "Everyone".

Then lower the MX record's TTL (300 seconds) a day ahead, remove the earlier
service's MX records (with Cloudflare Email Routing, disable it, which removes
its `route*.mx.cloudflare.net` records and its forwarding rules), and add
`MX 10 mail.example.org`. Send a message from an outside account (Gmail,
Proton) and see it arrive in Kutup Mail; `docker compose logs stalwart` shows
each delivery. To go back, restore the earlier MX records: mail queued at
senders is retried, and nothing already stored in Kutup is lost.
[`test/mail-proton.md`](test/mail-proton.md) is the end-to-end check with
Proton once mail flows.

Stalwart keeps its queue (mail not yet handed over) and its DKIM keys in the
`stalwart_data` volume. Back it up with the rest; losing it means
publishing new DKIM records.

---

## Security Hardening

- **Change all defaults** in `.env` before first start. The defaults are intentionally weak placeholders.
- **Firewall:** Only expose ports 80 and 443 (TCP), and UDP 443 for HTTP/3. All other services (PostgreSQL, SeaweedFS) must not be reachable from the internet. Without UDP 443 browsers stay on HTTP/2 over TCP; nothing breaks, it is only slower on lossy mobile links.
- **JWT_SECRET:** Use `openssl rand -hex 64`. A weak secret allows forging authentication tokens.
- **OPAQUE_SETUP_KEYS:** the keys sign-in's OPAQUE setups are sealed under
  (docs/plans/opaque.md). The server keeps each account's OPAQUE record, which
  is useless for guessing passwords offline as long as the setup's secrets are
  out of reach; they are stored sealed under this key, so a database dump or
  backup alone gives nothing to attack.
  - **Format:** `id:base64(32 bytes)`, comma-separated. The highest id is the
    current one. The server refuses to start on a malformed list, and on a key
    that does not open a stored setup.
  - **As a file:** the server also takes `OPAQUE_SETUP_KEYS_FILE`, a file
    holding the list (a mounted secret), never both. The bundled
    `docker-compose.yml` passes the variable; to use a file, set it in your
    own compose override or service unit instead.
  - **Back it up apart from the database,** never in the same place. Losing it
    signs no one in: every account then recovers with its recovery phrase and
    sets a new password.
  - **To rotate,** add a key with a higher id. Each account moves to the new
    setup at its next sign-in, silently. A setup no account uses any more is
    dropped. If the old key leaked, the accounts still on it stay open to
    offline guessing until they sign in again; ending their sessions hastens
    that.
  - **Never derived from `JWT_SECRET`:** rotating that one leaves passwords
    alone.
- **Referral codes:** stored only as HMACs under a key the server makes once and keeps in its database (`server_generated_keys`), so rotating `JWT_SECRET` leaves open codes working and a database restore keeps them; a new, empty database voids them.
- **ADMIN_ACCOUNT:** Keep this set — it defines the protected break-glass admin (never demotable/deletable). Rotate its password after first login, but don't remove the variable, or the break-glass protection lapses.
- **Quotas:** Set each account's storage quota (one pool for every app) in the admin dashboard to prevent abuse.
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

With Mail, the script also publishes Stalwart's setup image and prints a third
line, `KUTUP_STALWART_SETUP_IMAGE=…`; add `docker-compose.mail.yml` and
`docker-compose.mail-images.yml` to the compose files (after
`docker-compose.images.yml`) so it is pulled rather than built there.

### Scripted updates

`scripts/deploy.sh` does a whole update from the build machine over ssh, the
same way every time, and stops at the first failure:

```sh
KUTUP_DEPLOY_HOST=root@kutup.example scripts/deploy.sh <commit> --dry-run
KUTUP_DEPLOY_HOST=root@kutup.example scripts/deploy.sh <commit>
```

It refuses a commit whose CI on `master` did not pass. It pulls the three
images and records their digests and the running ones under `deploy-history/`
on the server. Then it runs both backups (see Database backups and Mail),
checks out the commit and validates its nginx config, and only then sets the
image lines in `.env` (keeping `.env.bak-<old>`), each pinned by digest as
`<repo>:<tag>@sha256:…` so a re-pushed tag never changes what runs. It starts
the stack and checks it:
migrations, backend errors, Stalwart's setup, storage, and every app host. It
keeps the new and the previous release's images and removes older ones; a
rollback is a deploy of the previous tag.
`--dry-run` stops after pulling and changes nothing. `KUTUP_DEPLOY_KEY`,
`KUTUP_DEPLOY_DIR` and `KUTUP_DEPLOY_HOSTS` are optional.

`--wipe` is for a clean-slate release: after typing the host name to confirm,
it drops the database volume and empties the bucket, keeping the backup
prefixes and Stalwart's volume (its DKIM keys). Every account and its data is
gone. It refuses a release without the squashed baseline migration.

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

Kutup does not depend on S3 object versioning: every object of a file lives
under `files/{id}/` (`original`, `versions/{versionId}`, `assets/…`,
`thumbnails/…`), every file version is an object of its own, and version retention
is Kutup's job (`docs/plans/drive-versions-v2.md` — the last day whole, then
hourly for a week, then daily up to each account's setting, 7 days to 10
years). Deletes remove every stored version of an object, so they are final
whether or not the bucket is versioned.

The `seaweedfs-init` Compose service creates the bucket (without versioning)
and applies `lifecycle.json`, only a safety net for a bucket that has
versioning from an earlier setup: anything overwritten or deleted outside
Kutup's own deletes (noncurrent versions, expired delete markers) goes after
a day. A bucket that already has versioning keeps it (S3 can only suspend
it); that is harmless. Re-run it after upgrading:
```sh
docker compose run --rm seaweedfs-init
```
