# Mail (Phase C)

**Status:** C1 done (2026-10-10); C2 next. Phase C of
[`../research/17-mail-calendar-contacts.md`](../research/17-mail-calendar-contacts.md),
after [`mail-address-keys.md`](mail-address-keys.md) (A) and
[`contacts.md`](contacts.md) (B).

## Goal

`name@kutup.dev` receives and sends mail. Mail from outside is encrypted to
the address key the moment it arrives (Proton's "zero-access"); mail between
Kutup users is end-to-end encrypted. Subject, addresses, dates and sizes stay
readable by the server (decision 1 of the design). Phase C has three parts:

| Part | Delivers |
|---|---|
| **C1. Infrastructure** (this plan in detail) | Stalwart in compose, inbound recipient check, LMTP receiver, encrypt-on-arrival, storage, pool accounting, DNS records except MX |
| **C2. Mail app** | `mail.kutup.dev`: folders, reading, compose and send (internal end-to-end, external over TLS through Stalwart), drafts, labels, search |
| **C3. PGP to the outside** | WKD and Autocrypt lookup, PGP encrypt, sign and verify, key import and export; then the MX switch from Cloudflare |

## Stalwart 0.16: configuration is data

The design assumed a TOML configuration. Stalwart 0.16 (the current line)
replaced it: apart from a one-line `config.json` naming the data store,
every setting is a JMAP object in Stalwart's own database, changed through
`/jmap` or `stalwart-cli apply` with a declarative plan file
(`UPGRADING/v0_16.md` in the reference clone). Measured on the dev VM with
`stalwartlabs/stalwart:v0.16.23` and `stalwartlabs/cli:1.0.12`:

- A fresh server with `config.json` = `{"@type":"RocksDb","path":"/var/lib/stalwart/data"}`
  creates its defaults on first start. `STALWART_RECOVERY_ADMIN=user:secret`
  gives an administrator that `stalwart-cli` authenticates as.
- `stalwart-cli apply --stdin` takes one JSON object per line:
  `upsert` (matched on a field such as `name`), `update` for singletons,
  `reconcile` (makes the type's objects exactly the plan's, removing others)
  and `create` for actions. Re-applying is idempotent.
- Secrets in the plan can name an environment variable
  (`{"@type":"EnvironmentVariable","variableName":"…"}`), so the plan is a
  static file in the repository and the secrets stay in `.env`.
- Applied settings take effect after an `Action` `ReloadSettings`, sent as
  a second `apply` (inside one plan it runs before `reconcile` removals).
- The chain works end to end: SMTP on 25 → the RCPT hook (bearer token, the
  recipient under test is the **last** entry of `envelope.to`) → LMTP to the
  relay route, byte-exact, with Stalwart's `Authentication-Results`,
  `Received-SPF` and `X-Spam-*` headers prepended. A rejected recipient gets
  the hook's 550 and nothing else changes.
- Memory: about 220 MiB idle with the spam filter's rules loaded.

## Transport

```text
outside MTA --25--> Stalwart --hook (HTTP, bearer)--> kutup /internal/mail/rcpt : accept, 550 or 452
                        '--LMTP :2424 (AUTH PLAIN)--> kutup receiver --> encrypt to address key --> S3 + Postgres
```

- **Stalwart** runs unmodified from `docker-compose.mail.yml`, image pinned,
  data in a volume. Its plan, `stalwart/plan.ndjson`, sets:
  - a `Domain` for the server name with `allowRelaying` (no Stalwart
    accounts: the hook alone decides who exists) and sub-addressing off
    (Kutup handles `name+tag@` itself);
  - an `MtaRoute` `Relay` named `kutup`, protocol `lmtp`, to the backend,
    with AUTH credentials from the environment, and the outbound strategy's
    route sending local domains to it;
  - an `MtaHook` for the `rcpt` stage with a bearer token, failing
    temporarily (4xx) when Kutup does not answer;
  - listeners: SMTP on 25 and the management HTTP on 8080 (internal only);
    IMAP, POP3, submission, Sieve and HTTPS removed;
  - logging to stdout; message size limit 50 MB (Proton's is 25 MB for
    attachments);
  - the `mx` route IPv4 only (`ipLookupStrategy: v4Only`) and the HELO name
    `mail.<domain>`, for C2's sending.
- A `stalwart-setup` service applies the plan and then the reload on every
  start (`stalwart/setup.sh`). Its image is Alpine with the CLI's static
  binary, since the CLI image has no shell to fill the plan's domain and
  host name in. It also gives Stalwart (uid 2000) a readable copy of the
  ACME certificate, which certbot leaves root-only, and checks daily for a
  renewed one. Stalwart's management port is never published.
- **The hook** (`POST /internal/mail/rcpt`, not routed by nginx, bearer
  token compared in constant time) accepts a recipient when its address,
  after lower-casing and dropping a `+tag`, is a Kutup address on this
  server with a primary key, and the account is active and has room in its
  pool. Unknown addresses get `550 5.1.1`, a full pool `452 4.2.2` (the
  sender keeps retrying, so the mail arrives once space is freed).
- **The receiver** speaks LMTP (RFC 2033) on an internal port and requires
  AUTH PLAIN with the shared secret. It answers per recipient, as LMTP
  requires, and re-checks each one: the hook ran before the size was known.

## Encrypt on arrival

For each accepted recipient, the receiver:

1. parses the headers with `mail-parser` (Stalwart's own parser, MIT or
   Apache-2.0) for the readable fields: subject, from, to, cc, reply-to,
   date, Message-ID, In-Reply-To, References and the attachment count;
2. encrypts the **whole message, byte-exact**, to the address's primary
   key: OpenPGP, SEIPD v1 with AES-256, binary (`kutup-crypto`
   `mail_key::encrypt_binary`). The client decrypts it and parses MIME
   itself; the original bytes stay available for export and the future
   IMAP bridge;
3. stores the ciphertext under `mail/{user}/{message}` and inserts the row,
   charging the pool, in one transaction under the pool lock. A failed
   insert removes the object; the sweep removes objects whose insert never
   ran.

Plaintext never reaches Postgres, S3 or a log. The parsed header values are
the readable fields; nothing from the body is kept (no snippet: C2 shows
snippets from the client's decrypted cache, as Proton does).

- **Duplicates:** a message whose Message-ID this address already received is
  acknowledged and not stored twice (mailing-list copies, retries after a
  lost LMTP reply).
- **Spam:** Stalwart's spam filter scores inbound mail. The receiver files
  the message under Spam when Stalwart's topmost `X-Spam-Score` header
  starts with `spam`; only the first occurrence counts, since a sender can
  add a lower one.
- **Threads:** a message joins the thread of a message it names in
  `In-Reply-To` or `References`, else starts a new one.

## Data (migration 085)

- `mail_messages`: id, user id, address id, thread id, folder (`inbox`,
  `drafts`, `sent`, `archive`, `spam`, `trash`), `seen`, `starred`,
  protection (`zero_access` now; `end_to_end` with C2), object key,
  ciphertext size, received at, sent at (the Date header), subject,
  from (address and name), to, cc and reply-to (JSON lists, bounded),
  Message-ID, In-Reply-To, References (bounded), attachment count.
  Indexes for the folder list by date, the thread, and Message-ID per
  address.
- Mail counts in the one storage pool: `mail_bytes` in the reconcile sums
  and "Mail" on the Storage page.
- Deleting an account deletes its mail rows and the `mail/{user}/` prefix.

## Configuration

| Variable | Use |
|---|---|
| `MAIL_INBOUND_TOKEN` | the hook's bearer token and the LMTP password; mail is off without it |
| `MAIL_LMTP_BIND` | the receiver's address, default `0.0.0.0:2424` when mail is on |
| `MAIL_HOSTNAME` | Stalwart's name (`mail.<domain>`), matching the IPv4 PTR |
| `STALWART_ADMIN_SECRET` | the setup service's administrator password |
| `MAIL_SMTP_PORT` | where port 25 is published, default `25` (the gate uses a loopback port) |

The backend publishes nothing new; Stalwart publishes port 25 only.

## Reading (for C2)

`GET /api/mail/messages?folder=` lists a folder's readable fields, newest
first, and `GET /api/mail/messages/{id}/content` returns the stored OpenPGP
message (`docs/api.md`, "Mail"). C2 adds moving, flags, deletion and
sending.

## DNS (except MX)

Documented in [`../self-hosting.md`](../self-hosting.md): `mail.<domain>` A
record and PTR, SPF `v=spf1 ip4:<address> -all`, the DKIM records Stalwart
generates (read from its `Domain.dnsZoneFile`), DMARC `p=none` with reports,
MTA-STS and TLS-RPT. The MX switch waits for C3.

## Slices

1. **C1a crypto and data:** `encrypt_binary` with vectors; migration 085;
   the pool, reconcile and Storage page entries; account deletion.
2. **C1b receiver:** the hook endpoint and the LMTP server with
   encrypt-on-arrival, threads, spam and duplicates, and the two read
   endpoints; unit tests for the protocol and the headers.
3. **C1c Stalwart:** `docker-compose.mail.yml`, plan, setup service,
   `.env.example`, self-hosting DNS; the gate below.

## Tests and gates

- `kutup-crypto`: `encrypt_binary` round trip and vectors (Rust and WASM).
- Server: LMTP state machine (pipelining, dot-stuffing, per-recipient
  replies, AUTH required, size limit), header extraction (encoded words,
  Turkish, missing fields), hook decisions, duplicates, threads, spam.
- `scripts/test-mail-inbound.sh` (`tests/mail_inbound_live.rs`): a real
  Stalwart and backend; mail to an account through port 25 with a `+tag`
  and capitals, an unknown address refused at RCPT, a duplicate not stored
  twice, a reply joining its thread, the stored message decrypting with the
  account's key to the bytes sent, another account refused, the pool
  charged; then, as administrator, a full pool deferring (452), a disabled
  account refusing (550) and a deleted account leaving no mail rows or
  objects.
