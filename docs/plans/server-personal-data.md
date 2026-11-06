# Server-side personal data: shredding, retention, audit, consent (before the wipe)

Status: **accepted** (2026-11-06; decisions below, by the main session within
what the user approved). Build in slices L1–L7, in order.

The server stores a little personal data in the clear: who signed in from what
browser, what the admin did, mail headers, and later a recovery email. These
mechanisms decide how it is kept, logged and destroyed. They are generic: any
deployment needs them, whatever its jurisdiction. They go into the core before
the wipe because they change the account record and stored formats, and every
account recreated after the wipe should have its records from day one.

Source of the requirements: the legal research in the private `kutup-legal`
repository (`plans/wipe-requirements.md`, sections A, D, G and H, at
`fdae5fa`). That research concerns the operator of kutup.dev. The code carries
no legal duty, and the core holds no jurisdiction-specific text or policy:
documents, consent purposes beyond the two below, and retention periods are
configuration. A private fork can add its own on top.

Out of scope: hosting location and billing (after the wipe), legal-request case
handling, edge traffic logs (both operator tooling, outside the server binary),
trial states, a test notice, a registration cap.

Never stored, by any of this: IP addresses, raw user-agent strings, phone
numbers, birth dates, national ids, message or file content, file names. No key
escrow and no server-side decryption path for end-to-end encrypted data.

## What exists today (wipe-2, 7b70e0aa)

| Area | Today |
|---|---|
| Account state | `users.is_active` only. Admin delete is immediate and synchronous (`handlers/admin.rs:453`); no self-service deletion; no background deletion; no legal hold. |
| Recovery email | Not built (`account-identity.md`, "Recovery email": planned `user_recovery_emails`). |
| User agents | Raw `User-Agent` (up to 512 characters) in `auth_sessions.user_agent`, copied into `account_security_events.acting_user_agent`; returned raw and parsed in the browser (`describeUserAgent`). Feedback stores `navigator.userAgent` (300 characters). |
| Retention | Security events: pruned on every insert to 365 days or the newest 500 (`security_events.rs:138`). `auth_sessions`: never deleted. |
| IPs | No table stores one. Read only for in-memory rate-limit keys. |
| Logs | `account_security_events` (user-visible; no sign-ins), `admin_audit_log` (admin mutations only, best effort, no reads). One database role for everything; nothing is append-only. `security-log.md` is an unaccepted draft. |
| Server-held keys | None per account. TOTP secrets are plaintext; two columns are sealed under env key lists (`OPAQUE_SETUP_KEYS`, `MAIL_FORWARDING_KEYS`). |
| Mail metadata | `mail_messages`: subject, from, to/cc/bcc, reply-to, Message-IDs in the clear (the "readable fields" the sender's browser supplies). |
| Share links | `public_shares` (Drive and Photos): `removed_at` (owner or admin takedown) and `expires_at`, both `410`. No per-account or site-wide switch. |
| Legal documents, consent | Nothing recorded at signup; no consent records; federation is site-level only. |
| Backups | `pg_dump`, AES-encrypted, kept 30 days. A deleted account stays in every backup. |
| nginx | PROXY protocol on all TLS listeners; `real_ip_header proxy_protocol`. No custom log format. |

## A2. A per-account server key (crypto-shredding)

Every account gets a random 32-byte **account data key**, held by the server.
Server-side personal fields are sealed under it. Destroying the key destroys
those fields everywhere they are copied, backups included, without finding
each copy.

- **Format.** A sealed field is `suite (u16) ‖ key generation (u32) ‖ nonce
  (24) ‖ XChaCha20-Poly1305(value)`. The AAD binds the table, the column, the
  row's id and the account id, so a value can't be moved to another row or
  account. This is Rust in `kutup-crypto` (`server_data`, with vectors), used
  only by the server.
- **Where the key lives.** `account_keys.account_data_keys(user_id,
  sealing_key_id, generation, wrapped, created_at)`. Each key is wrapped under
  a key-encryption key derived (HKDF, its own label) from an entry of the
  server key list, `OPAQUE_SETUP_KEYS`. The list already seals the OPAQUE
  setups and the group send keys, is kept out of the dumps and is backed up
  apart, so a second list would add nothing (decided in L1, 2026-11-06). A
  database dump without the list opens nothing.
  - Each row names the entry that wraps it (`sealing_key_id`). After an entry
    is added, keys move to it when next used and in batches of 500 a minute;
    never all at start.
  - The server refuses to start without an entry that still wraps keys,
    naming the entry and the count; self-hosting.md says how to check before
    removing one.
  - A key is made when the account first has something to seal, and goes with
    the account (the foreign key cascades) and at an account reset.
- **Backups.** Deleting the key row is not enough while 30 days of dumps still
  hold it. Two measures together:
  1. `account_data_keys` lives in its own schema, which the database dump
     leaves out (`--exclude-schema`). Its own small, separately encrypted
     dump has a short retention: a site setting, default 7 days. Within that
     many days of a deletion, no copy of the key remains anywhere.
  2. A restore replays the destruction log (A7). Before the restored server
     serves anything, it destroys the keys of every account the log
     recorded as destroyed after the dump was taken. The log is append-only
     and kept for years, so it outlives every dump.

  Both, so restoring any older backup can never bring back a deleted
  account's key (decision 2).
- **What is sealed:**
  - the parsed user-agent family in sessions and security events (A10);
  - the TOTP secret (today plaintext);
  - the recovery email, sealed from the start when it is built;
  - the mail metadata (below).

  Never sealed: anything the server must query on (ids, timestamps, states,
  sizes, quota counters).
- **Mail metadata** is the open item:
  - Today the server sorts by time, threads by Message-ID, and the list shows
    subject and sender without opening anything.
  - Sealing subject, from, to/cc/bcc and reply-to under the account key keeps
    the list working: the server opens them to answer, as it does any sealed
    field.
  - Message-ID, In-Reply-To and References get a keyed-hash lookup column for
    threading (HMAC under a subkey of the account key), and their sealed
    value.
  - Whether any server-side search reads subject or sender in SQL decides
    whether that search moves to the browser's index (Mail body search
    already does). To check before L7.
- **Key generations.** A new generation per account is possible (re-seal, then
  drop the old one), but nothing needs it before the wipe.

## A5. Account states and legal hold

- **`users.state`** (text, CHECK): `active`, `suspended`, `closing`. It
  replaces `is_active`: `suspended` is today's "not active", with a
  `suspended_reason` (`admin`, `operator_order`, `security`) and
  `state_changed_at`.
- **`closing`:** the account was asked to be deleted, by its owner or an
  admin, and is waiting out a grace period: a site setting
  `account_closing_days`, default 14. In that time the account can't sign in
  except to cancel. Then a background job deletes it.
- **"Deleted" is not a row** (decision 1). A deleted account's row goes: the
  purge that runs today, then the account data key is destroyed, then a
  destruction event is recorded (A7). The record of the deletion is that
  event, which holds no personal data. Username holds keep their own
  mechanism and table (`account_names`), unaffected.
- **`purpose_ended_at`** (timestamptz): set when the account is closed. It is
  the start of every retention clock that runs on after an account ends, in
  the logs and the destruction log.
- **Legal hold:** `legal_hold_reference` (text, nullable; null = no hold), plus
  `legal_hold_at` and the admin who set it. While set:
  - no deletion job, admin delete, account wipe or retention purge removes
    anything of the account;
  - the attempt fails, saying why;
  - setting or clearing a hold is an audited admin action (A8).
- **Self-service deletion** (missing today, and the reason `closing` exists):
  - Settings → Account → Delete account.
  - It needs re-authentication (as other sensitive changes do) and moves the
    account to `closing`.
  - An email notice comes once the recovery email exists.
- **Fork extension:** the core's states are closed. A fork that needs trial
  states adds its own column (e.g. `plan_state`) and gates sign-in with its own
  check, instead of widening the core's CHECK.

## A7. Destruction events

`destruction_events(id, at, category, subject, method, actor, reference)`,
append-only (A8's rules):

- `category`: `account`, `security_events`, `sessions`, `share_link`,
  `backup`, …;
- `subject`: an HMAC of the account id under a server key, so the log names
  nobody, yet a restore (A2) can match it against the accounts it restores;
- `method`: `crypto_shred`, `delete`, `anonymise`;
- `actor`: `user`, `admin`, `job`;
- `reference`: a job name or an admin-action id.

Retention is a site setting, default 3 years. The core emits these events and
keeps them; reports on them are operator tooling.

**As built (L4, A5 and A7):**
- `users.state` (`active`, `suspended` with `suspended_reason`, `closing` with
  `closing_by` and `closes_at`), `state_changed_at`, `purpose_ended_at` (set
  when closing, cleared when kept). `is_active` stays, generated as
  `state = 'active'`, for the queries that route, deliver and sign in;
  nothing writes it.
- Closing: `POST /api/user/close` with a reauth grant (`close`), or an
  admin's `POST /api/admin/users/{id}/close`. Every sign-in and grant ends. A
  sign-in that passes every step gets no session but a grant (`keep`, no
  session, minutes); `POST /api/auth/keep` makes the account active again and
  answers as the sign-in. An admin keeps it with `isActive: true`. Either
  only before `closes_at` (or under a hold): after it the job may be deleting
  the account, and a keep would leave it active and emptied. The
  closing job (`crate::account_closing`, every five minutes, 20 at a time)
  deletes accounts past `closes_at` (`account_closing_days`, default 14).
- Deletion (`account_closing::destroy`, for the job and an admin's delete):
  the purges, names held, account id retired, the row deleted (its data key
  cascades), and the destruction event, in one transaction that checks the
  hold again.
- Legal hold: `legal_hold_reference`, `_at`, `_by`; set and lifted by an admin
  (`user.legalHold.set` / `.clear` in the admin log). It refuses an admin's
  delete and reset (`409 legalHold`), holds the closing job back, and the
  retention jobs pass the account's sessions and security events by; the
  admin log is pruned only up to its oldest row about a held account, so the
  chain stays whole.
- The log is `account_keys.destruction_events`, not in `public`: the key dump
  holds it, so a restore replays a log as new as its keys. Subjects:
  `kutup_crypto::server_data::destruction_subject`, HKDF of a server key list
  entry over the account id, one per entry present (`subject_key_ids`,
  `subjects`), so a rotation later still matches. Bulk deletions (security
  events, admin log, sessions, the log itself, by retention) are one row with
  a `count` and no subject. `share_link` and `backup` come with L5 and with a
  backup job that records its pruning.
- Replay: at start, before serving, every account whose subject the log holds
  loses its data key and is closed at once (`closing_by = 'restore'`), for
  the closing job to delete it again.
- No email notice yet: it comes with the recovery email.

## A8. Append-only security and admin logs

- **Two logs stay two:**
  - `account_security_events` is the account's own, shown to its owner;
  - `admin_audit_log` is the operator's.

  Both become append-only at the database level.
- **Roles.**
  - The server runs as a role with `SELECT, INSERT` on both logs and on
    `destruction_events`, and no `UPDATE` or `DELETE`.
  - The owner role, which runs migrations, also runs a retention job: a
    separate connection (`DATABASE_OWNER_URL`) that deletes only rows past
    their retention.
  - Single-role self-hosting keeps working (decision 3): if no owner URL is
    set, the server runs the job on its own connection and says the
    append-only guarantee is off, loudly at start, in `check-config`, and as
    a standing warning in the admin console. kutup.dev runs two roles.
  - docs/self-hosting.md says how to create the two roles.
  - **The insert-time pruning goes** (`security_events.rs:138`); the retention
    job does it.
- **Hash chain on the admin log:**
  - each row stores `previous_hash` and `row_hash = SHA-256(previous_hash ‖
    canonical row)`;
  - inserts take an advisory lock, since admin actions are rare;
  - the admin page shows whether the chain verifies.

  Not on the security events: they are per account, user-visible, and pruned
  by count.
- **What is logged, added to today's kinds:**
  - **Sign-ins:** `signIn`, `signInFailedPassword` (only when the pending
    OPAQUE login names a real account), `signInFailed2fa`, `signOut`,
    `sessionRevoked`, `allSessionsRevoked`. These are the kinds from
    `security-log.md`, with repeated failures folded into one row with a
    `count`.
  - **Admin access to an account's data** (opening a user's page, its
    sessions, its security events, its storage breakdown):
    - one `admin.view` audit row per admin request that returns account
      data;
    - the account's own log gets `adminAccess` (Proton shows the same).
  - **Support access:** none exists. When an organization or support
    "sign in as" is built (`organizations.md`), it logs to both logs from
    the start.
  - Legal hold set or cleared, state changes, documents published (A3).
- **Retention, as site settings:**
  - security events: 365 days, plus the newest-500 rule;
  - admin audit: 730 days;
  - destruction events: 3 years.

  The account's security page says how long its events are kept.
- **`security-log.md`:** this note takes over the draft. It keeps the draft's
  events and folding and drops its `advanced` mode and `ip` column (no table
  stores IPs).

**As built (L2):**
- The owner role is `DATABASE_OWNER_URL`; with the bundled compose,
  `POSTGRES_APP_USER` and `POSTGRES_APP_PASSWORD` make the server's role.
- At each start the owner grants that role every table, then takes back UPDATE,
  DELETE and TRUNCATE on the two logs and gives `UPDATE (count)` on the security
  events, the one updatable column, so failures fold.
- Foreign-key cascades still delete an account's events: Postgres runs them as
  the table's owner.
- The retention job runs hourly on the owner's connection.
- `GET /api/admin/activity/verify` walks the chain and says whether the logs
  are append-only.
- Admin access means opening one account's limits, mail-domain overrides or
  mail-sending state: account content is end-to-end encrypted, so these are
  what an admin sees of an account.

## A10. User agents: a parsed family, sealed, with retention

- **Parsing:** the server parses the `User-Agent` header once, at sign-in, into
  `{ browser, browserMajor?, os }`:
  - `browser`: Firefox, Chrome, Edge, Safari, Opera, Samsung Internet, Kutup
    CLI, other;
  - `os`: Windows, macOS, Linux, Android, iOS, ChromeOS, other;
  - the major version is kept: a security page that says "Firefox 98" helps
    spot an old device.

  The raw string is never stored.
- **Sealing:** the family is sealed under the account data key (A2) in
  `auth_sessions.client_sealed` and `account_security_events.client_sealed`.
  APIs return the three fields; `describeUserAgent` leaves the browser.
- **Feedback** sends the same parsed family, not `navigator.userAgent`.
- **Retention, as site settings:**
  - ended sessions (revoked or expired): deleted after
    `session_record_grace_days`, default 30;
  - security events: deleted per A8.

  Both through the retention job, with destruction events.
- **IPs:** none in the database, as today. The edge passes the PROXY protocol
  address and port. The core keeps them available to nginx
  (`$proxy_protocol_addr`, `$proxy_protocol_port`) and never removes the
  `proxy_protocol` listeners; any edge log format is operator configuration.

**As built (L3):**
- `crate::client_family::parse` names Firefox, Chrome, Edge, Safari, Opera,
  Samsung Internet and the CLI, with the major version, and Windows, macOS,
  Linux, Android, iOS and ChromeOS.
- The family is sealed as `client_sealed` on `auth_sessions` and
  `account_security_events`, for each row. An event opens its session's family
  and re-seals it for itself, so it outlives the session.
- Ended sessions go after `session_record_grace_days` (default 30), unless a
  session forked from one still lives.
- Feedback sends the family the browser parses ("Firefox on Linux"), not
  `navigator.userAgent`.

## A11. Share-link controls

- **Operator block:** `public_shares` gains `blocked_at`, `blocked_reason`
  (`legal_order`, `abuse`, `other`) and `blocked_reference` (admin-only).
  - A blocked link answers `451` for `legal_order` and `410` otherwise. The
    code is `link_blocked` with the reason, so the public page says why;
    owner and admin takedowns keep `link_removed`.
  - Unblocking is possible; both directions are audited.
- **Per account:** `users.public_sharing` (`on`, `off`), which an admin sets
  per account. While `off`, the account can't create public links, and its
  existing ones answer `410 sharing_off`.
- **Site-wide:** a site setting `public_sharing`: `on`, `off`, or
  `signed_in` (only someone signed in to this server can open a public link).
  - Applies at creation and when a link is served.
  - The Drive and Photos share dialogs say why sharing is off.
  - `signed_in` keeps a test deployment's links among its own accounts.
- **Meeting call links:** a way into a call, not a publication. They aren't
  covered.

## A3 and A4. Notice acknowledgements and consents (separate records)

- **Documents:** `legal_documents(id, kind, version, language, url, sha256,
  published_at, required_at_signup)`.
  - The text lives elsewhere (the operator's site or the fork). The core
    stores the URL and the SHA-256 of the exact text shown.
  - `kind` is configuration (`terms`, `privacy_notice`, …), not a CHECK list.
  - Admins publish a version in the admin UI. An audited action, and a
    published version is never edited.
  - No document published means nothing is asked: a self-hoster's signup is
    as today.
- **Acknowledgements** (the notice was shown and confirmed; not consent):
  `document_acknowledgements(user_id, document_id, at, context)`.
  - `context`: `signup`, `update`.
  - Append-only.
  - At signup, `register/finish` takes the ids of the documents shown. The
    server checks they are the current `required_at_signup` versions and
    stores them in the account's creating transaction, so no account lacks a
    record.
  - A new required version is shown at the next sign-in.
- **Consents** (per purpose, separate and withdrawable):
  `consents(id, user_id, purpose, given, document_id, at, channel)`.
  - Append-only. The current state per purpose is the latest row.
  - `GET/PUT /api/user/consents`; Settings → Privacy lists each purpose with
    its document version and lets the person withdraw it.
  - **Purposes from day one:** `federation_abroad` and `marketing`. There is
    no purpose for storing the account abroad: that rests on the operator's
    contracts with its providers, not on the user.
  - **A per-account federation switch** (decision 4): federation is
    site-level today, so the account gets a "talk to other servers" switch
    (its default a site setting). Turning it on asks for the
    `federation_abroad` consent when a document for the purpose is published;
    withdrawing the consent turns it off. Built in L6.
  - `marketing` is recorded only: there are no marketing messages.

## Slices (after review, in this order)

| Slice | Contents | Size |
|---|---|---|
| L1 | A2: `server_data` format and vectors, `account_data_keys` under the server key list, key schema and its own dump; TOTP secret sealed (the restore replay comes with A7, L4) | M |
| L2 | A8: two roles, retention job, append-only grants, hash chain on the admin log, sign-in events, admin-access events, retention settings | M |
| L3 | A10: UA family parser, sealed client columns, API and Account app, feedback, session retention | S–M |
| L4 | A5 and A7: states, closing job, legal hold, self-service deletion, destruction events, restore replay | M |
| L5 | A11: operator block, per-account and site-wide switches, share dialogs, public pages | S–M |
| L6 | A3 and A4: documents, acknowledgements at signup and update, consents API and Settings, the per-account federation switch | M |
| L7 | A2 for mail metadata: sealed headers, keyed-hash threading, search check; before the wipe, as it is a format (decision 5) | M |

Each slice adds en and tr strings, site settings in the registry (with the admin
UI), docs (`api.md`, `self-hosting.md`, the Account app's help), and live tests;
L2 and L4 also a backup-restore test of the replay.

## Decisions (2026-11-06)

1. A deleted account leaves no row; its destruction event is the record.
   Username holds are unaffected.
2. Both the key schema with its own short-retention dump and the replay of
   the destruction log on restore.
3. Two database roles, with a single-role fallback that warns at start, in
   `check-config` and in the admin console. kutup.dev runs two roles.
4. A per-account federation switch, where `federation_abroad` is asked.
5. Mail metadata is sealed before the wipe (L7).
6. Defaults, all site settings (per account where a setting limits one
   account): closing 14 days, key-dump retention 7 days, ended sessions
   30 days, security events 365 days, admin audit 730 days, destruction
   events 3 years.
7. TOTP secrets are sealed under the account data key (L1), so they are
   shredded with the account.
