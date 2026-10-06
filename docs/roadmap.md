# Production-readiness roadmap

Kutup is **pre-production**: there is no public release yet (until the first
`v*` git tag). This document is the canonical list of everything
between today and "ready to tag v1".

It is the bridge between `docs/` (current state, authoritative) and
`docs/research/` (forward-looking design notes that may never ship). The blocker
and follow-up sections are remaining work; the Chat phase table is retained as a
gate record and explicitly labels completed slices.

**When a feature lands**, move it out of this file and update the appropriate `docs/*.md`. The roadmap should always describe the gap to v1, not the past.

---

## What "production-ready" means for kutup

The bar for the first `v*` tag:

1. **No silent stubs in admin-facing UI.** Every clickable action that exists in the UI must work end-to-end. No "wire-up pending" toasts in shipped builds.
2. **Deletion is recoverable.** ✅ Shipped: owner-scoped trash with restore + permanent delete, and an hourly retention sweeper (`TRASH_RETENTION_DAYS`, default 30). See `docs/api.md` → Trash.
3. **Self-hosters can recover broken users without SSH.** ✅ Shipped: force-disable 2FA (lost authenticator), re-enable account (accidental disable), rotate temp password (first-login accounts), and the destructive wipe for users who lost both password and recovery phrase — all from the responsive web admin UI. `docs/research/10-admin-password-reset.md` records why "reset password" is two actions under E2EE.
4. **Builds are signed.** Unsigned binaries trigger macOS Gatekeeper and Windows SmartScreen warnings that look like malware to non-technical users.
5. **Admin actions leave an audit trail.** ✅ Shipped: every mutating admin endpoint writes an `admin_audit_log` row; `GET /admin/activity` serves the feed and the Recent-activity cards render it in both responsive web layouts. See `docs/api.md` → Admin.
6. **Basic abuse protection.** ✅ Shipped: per-IP limits on login/preflight/register/recovery/federation/admin (env-overridable `RATE_LIMIT_*`), per-account login lockout (`LOGIN_LOCKOUT_*`), per-token TOTP blocking, and proxy-aware client-IP resolution (X-Real-IP). See `docs/self-hosting.md`.
7. **Documentation tracks reality.** ✅ Shipped: full docs sweep against the shipped code (stale Go-stack references scrubbed, env vars + endpoints verified), and every HTTP operation is annotated with `#[utoipa::path]` so `GET /api-docs/openapi.json` lists the complete API (a coverage test in `openapi.rs` keeps it honest). Interactive Swagger UI remains deferred (see below).

Items below are organized by **whether they block v1** vs. whether they can ship in a subsequent release.

---

## Blockers for v1 (must-have)

### V1 cryptographic and identity cutover

Kutup is still preproduction, so the first stable tag must freeze the clean
format rather than preserve development-only ciphertexts or trust machinery.
This destructive-change permission expires at the first stable `v*` tag;
afterward `docs/crypto-agility.md` requires versioned readers, authenticated
migrations, peer capability windows and no silent downgrade.

The normative checklist is
[`docs/draft/v1/security-review-follow-ups.md`](draft/v1/security-review-follow-ups.md).
The following are release blockers:

- one parameterized Argon2id root with HKDF-separated KEK/login keys, a derived
  recovery-auth proof that never exposes recovery entropy, and suite-bearing
  account envelopes;
- canonical Rust `kutup-crypto` used by the browser through WASM, subject only
  to the documented per-operation 10× primitive-adapter exception;
- one account-signed `AccountManifestV1`, complete history, durable TOFU/QR
  pins, explicit account-incarnation reset, and removal of the global
  transparency log/checkpoint/proof/monitor stack;
- typed context-bound XChaCha Drive/profile/collaboration envelopes,
  authenticated X25519-HPKE named shares and owner-authenticated collection
  epochs;
- an administrator-controlled 1–10 active-device limit (default and hard cap
  10), enforced identically by every Chat and identity path;
- Signal-class web-device continuity: **active-installation review, editable
  account-private installation labels, safe revocation, and always-on
  account-local E2EE Chat backup are implemented.** Numeric device IDs remain
  immutable protocol-routing metadata.
  Every durable display mutation enters a crash-safe encrypted outbox; the
  homeserver stores an opaque signed base-plus-tail restore point and separately
  encrypted media under an administrator-controlled Chat quota. A recovered
  browser uses the existing Drive recovery setup and restores from the server;
  device-to-device history transfer is not supported. Missing or invalid backup
  state produces an explicit history-loss warning rather than a silent empty
  inbox;
- MLS suite `0x0003` and real 256-account/2,560-leaf group gates; and
- confidential broadcast for 1,000,000 accounts and up to 10,000,000 device
  grants using the separate LKH plus small-MLS-control-group design.

The format inventory and threat models are
[`docs/v1-format-inventory.md`](v1-format-inventory.md),
[`docs/drive-security-threat-model.md`](drive-security-threat-model.md), and
[`docs/broadcast-security-threat-model.md`](broadcast-security-threat-model.md).
The exact third-party ownership boundary is
[`docs/cryptographic-dependencies.md`](cryptographic-dependencies.md).

### Signed builds

Release builds are currently unsigned. The CLI archives carry checksums only,
and a future desktop app will need macOS notarization and Windows
Authenticode, or Gatekeeper and SmartScreen will warn non-technical users.

| What's needed | Where |
|---|---|
| Apple Developer ID for macOS signing + notarization | external — requires Apple Developer Program ($99/yr) |
| Microsoft Authenticode certificate for Windows | external — DigiCert / Sectigo (~$300/yr) |
| Native iOS signing, TestFlight/App Store Connect, entitlements, and opaque production icons | external + sibling `kutup-ios` repository |
| Native Android upload key, Play App Signing/Console, and release metadata | external + sibling `kutup-android` repository |
| Documentation: `docs/release-signing.md` covering how to rotate keys | new doc |

---

## Important (should-have, can ship after v1)

These aren't blockers — kutup can release without them — but they're real production gaps and should land in v1.1 or shortly after.

### SMTP integration

Without SMTP, kutup can't:
- Send welcome emails (we cut the "Send welcome email" toggle from the admin create-user dialog because there's no flow)
- Send password-reset links (admins currently share temp passwords out-of-band)
- Send share notifications ("Alice shared a folder with you")

| What's needed | Where |
|---|---|
| Backend: SMTP client + env-var config (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`) | `crates/kutup-server/src/email.rs` (new) |
| Backend: template system for welcome / reset / share emails (HTML + plaintext) | `crates/kutup-server/templates/email/` |
| Frontend: re-enable the "Send welcome email" toggle in `AdminCreateUserDialog` (currently dropped) | `frontend/src/components/admin/AdminCreateUserDialog.tsx` |
| Documentation: `docs/email.md` setup guide | new |

### Admin · System status endpoint

The desktop Admin Overview's System card is hidden today because the backend doesn't expose uptime, TLS expiry, or the public URL. Useful for self-hosters at a glance.

| What's needed | Where |
|---|---|
| Backend: `GET /admin/system` returning `{ uptime, tlsExpiry, publicURL, version }` | new handler |
| Backend: track process start time, parse cert expiry from TLS config | service-level |
| Frontend: unhide the System card on `AdminOverviewTab` | `frontend/src/components/admin/AdminOverviewTab.tsx` |

### Admin · Required-2FA + Drive-default-quota + trash-retention settings

`/admin/settings` now exposes registration, the dedicated default Chat quota,
and mailbox/temporary-media retention in desktop-width and mobile-width web
layouts. Server-driven
required 2FA, a default Drive/general quota, and runtime trash retention remain
unimplemented; their cards stay hidden.

| What's needed | Where |
|---|---|
| Backend: extend `admin_settings` JSON with `require_2fa_users`, `require_2fa_admins`, `default_storage_quota_bytes`, and `trash_retention_days` | `crates/kutup-server/src/handlers/admin.rs` |
| Backend: enforce `require_2fa_users` on next sign-in (force-set TOTP within N days or block) | `crates/kutup-server/src/handlers/auth.rs` |
| Backend: apply `default_storage_quota_bytes` when creating new users | `crates/kutup-server/src/handlers/admin.rs` |
| Frontend: add the remaining controls without disturbing the shipped Chat-storage controls | `frontend/src/components/admin/AdminSettingsTab.tsx`, mobile equivalent |

### Admin · Danger-zone actions

The design has "Re-index search" and "Purge soft-deleted files now" in a Settings → Danger zone card. Both hidden today.

| What's needed | Where |
|---|---|
| Backend: `POST /admin/actions/reindex-search` (kicks off the encrypted-search reindex) | new |
| Backend: `POST /admin/actions/purge-trash` (forces the trash retention sweeper — `jobs::trash_sweep_once` — to run now) | new |
| Frontend: unhide the danger zone card | both admin Settings tabs |

### Native iOS and Android apps

The dedicated `kutup-ios` and `kutup-android` apps are active work in sibling
repositories and are not release-ready. The implemented `kutup-client-ffi`
boundary is only one dependency of those products; native UI integration,
platform lifecycle, secure storage, complete Direct/MLS/media/backup parity,
packaging, signing, store metadata, and real-device acceptance remain gated in
their own plans. See [`mobile-build.md`](mobile-build.md) and
[`chat-native-bindings.md`](chat-native-bindings.md).

### Responsive web · mobile selection mode

Per the design + user direction: long-press / "Select" button on mobile turns the page into Google-Drive-style full-screen takeover with checkboxes, top "Cancel · N selected · Select all" bar, bottom action bar (Share / Move / Delete / More).

Desktop selection is **explicitly carved out** — kutup keeps its existing no-layout-shift selection pattern there.

| What's needed | Where |
|---|---|
| Frontend: selection state in MobileShell or a context | `frontend/src/components/mobile/` |
| Frontend: row checkboxes on FolderTile + FileListRow when selection mode is on | mobile components |
| Frontend: replace MobileBottomNav with a selection action bar while active | shell |
| Frontend: replace MobilePageHeader with the selection top bar while active | shell |

### Responsive web · optional file filters, view modes, and gestures

The current Files page intentionally removed the old non-functional category
chips and list/grid toggle. Add them only with complete filtering, persistence,
keyboard, and touch behavior.

| What's needed | Where |
|---|---|
| Frontend: wire chip filters to filter the rendered items | `frontend/src/pages/mobile/MobileFilesPage.tsx` |
| Frontend: List vs Grid toggle with localStorage persistence | same |
| Frontend: iOS-style swipe-to-share / swipe-to-delete on file rows | new |

### Responsive web · page transitions

Sub-pages currently appear / disappear instantly. iOS users notice the missing slide-in / slide-out.

| What's needed | Where |
|---|---|
| Frontend: a thin `<RouteTransition />` wrapper that animates push (left → right) and pop (right → left) | `frontend/src/components/mobile/` |

### Responsive web · recently shared by me

The Shared tab has an empty hero for this section. Data is derivable from the shares table; just needs wiring.

### Responsive web · viewer touch tweaks

Excalidraw / photo / PDF viewers work on mobile but some tap targets are desktop-sized + the top status bar overlaps content in places. **Carve-out**: the viewers themselves are NOT redesigned (user said they're "clean and useful"). Just touch + safe-area tweaks.

### Native mobile · push notifications

Native iOS/Android notifications for shared-file and Chat events. Not v1.

| What's needed | Where |
|---|---|
| Apple Push Notification Service setup | external |
| Backend: APNS sender + per-user device-token registry | new |
| Native clients: APNS/FCM registration, permission, and presentation | sibling iOS/Android repositories |

### Responsive/native mobile · recovery-phrase management

The mobile Encryption Keys page explains the recovery boundary and links to
account recovery; it does not claim that an authenticated session can display
or rotate the stored phrase. A future phrase-rotation product needs a separate
security design, backend contract, and word-by-word confirmation flow.

### Backup / restore CLI

The database half exists: `scripts/backup-postgres.sh` stores encrypted dumps in the object store and restores them (`docs/self-hosting.md`, "Database backups"). Still open: copying the object store's blobs elsewhere (a second copy of the ciphertext), a point-in-time-consistent pair of database and blobs, and `kutup backup` / `kutup restore` subcommands in the Rust CLI (`crates/kutup-cli`) to wrap both.

---

## V1 major track · Federated E2EE chat ("ileti")

The shipped web track provides libsignal Direct Chat/Note to Self and OpenMLS
private groups with encrypted media over the same application edge and
authenticated federation stack as Drive. Chat objects use the same SeaweedFS
infrastructure but separate formats, references, keys, and a dedicated quota;
they are not Drive files. The current UI is part of the main responsive web app,
not a required second domain. Voice/video calls remain a later phase.

The full architecture is captured in `docs/research/11-federated-chat.md` (libsignal v0.97.2 study, Matrix take-vs-leave, single-443 topology, risks), the wire-contract fixes in `docs/research/12-chat-improvements-for-clients.md`, and — decisively — the adversarially-verified comparative study `docs/research/13-chat-architecture-comparative-research.md` (Signal/Matrix/XMPP + local libsignal/Prosody/ejabberd/Monal code). Direction is committed and validated. **Locked decisions:** libsignal-protocol as a pinned wrapped dependency (AGPL-compatible, never reimplement the ratchet); transport-only federation (signed s2s over 443 + `.well-known`, no Matrix-style replicated room state — the DAG is CVE-confirmed as the mistake); PQ (PQXDH + SPQR) always-on with a versioned suite registry, algorithm agility as a protocol mechanism **not** a user downgrade toggle.

The normative wire contract the three clients freeze against is **`docs/chat-protocol.md`** (v1) — it consolidates the wire-affecting decisions from `11-`/`12-`/`13-` into one spec, tagging every field **[IMPL]** (phase-2 server, frozen), **[ADD]** (additive, phase-2b), or **[RSV]** (reserved now, implemented later so it's not a breaking migration). Implement against that.

**Current group decision:** the earlier GV2/sender-key proposal is superseded by
the RFC 9420 MLS architecture in [`chat-mls.md`](chat-mls.md). Direct Chat and
Note to Self remain on pinned libsignal; private groups and the small broadcast
administrator control group use OpenMLS. Groups use owner-approved,
dynamically replaceable multi-server ordering authorities rather than a
permanent homeserver. **Account/device authenticity** is a V1 requirement.
Sealed sender remains all-or-nothing with no identified fallback, and all
federation continues to use the common authenticated transport rather than a
room DAG.

Phases (each lands as its own PR-series; the table order is the current delivery
priority, while the stable phase labels keep existing specifications and test
names unambiguous):

| # | Slice | Gate |
|---|---|---|
| 1 | **Spike**: `libsignal-protocol` + `spqr` on wasm32 | ✅ **GO** (2026-07-12, `spikes/libsignal-wasm/`) — compiles for the browser target on stable, full PQXDH+Triple-Ratchet round-trip executes in wasm; web client shares `kutup-chat-core` |
| 2 | Server slice: `kutup-chat-proto` + prekey directory, per-device mailboxes, WSS drain | ✅ landed — `crates/kutup-chat-proto`, migration 021, `handlers/chat.rs`, `chat_hub.rs`, nginx `/api/chat/ws`; full REST + WS contract smoke-verified against the live stack (incl. one-time-prekey consumption, last-resort fallback, the 409 missing/stale/extra device contract, live envelope push). Playwright chat spec lands with phase 2b |
| 2b | Shared core + minimal 1:1 reference web UI | **Implemented and live-stack verified.** Includes durable typed inbound journal/quarantine, SQLCipher/IndexedDB stores, crash-safe registration/prekeys, signed manifests, WASM transport, Web Locks, REST+WS reconciliation, history, Note to Self, and ordinary linked-device sent transcripts. Web remains the product client until the messaging milestone is complete; native packaging/integration is not a gate. |
| 3 | Web federation foundation | **Implemented and two-server live verified:** canonical `username@server`, typed conversations, one persistent v2 server identity, signed `.well-known` endpoint/capability discovery, immutable identity history and authenticated rotation, strict RFC 9421/9530 request/response authentication, replay reservation, DNS-rebinding/SSRF-safe resolution, durable per-destination in-order Chat delivery, device-mismatch recovery, terminal rejection, and sequence-gap replay. Drive now uses that same stack for signed account lookup, domain-bound fragment capabilities, invite acceptance, file lists, idempotent upload/delete, persisted ciphertext digests, and verify-before-release streaming downloads. The isolated harness proves the Drive round trip, that Chat reuses a Drive-established pin, and that Chat retry survives an origin restart while the destination is offline. The generic responsive admin control plane provides a global stop, feature-scoped `disabled`/`allowlist`/`blocklist`/`open` admission and trust floors, directional domain rules, shared Chat/Drive diagnostics, peer search/trust filters, retry-one/retry-visible workflows, TOFU verification, exact immutable quarantine/history evidence, break-glass re-pin, and filtered audit presentation/CSV export. A disabled feature is omitted from discovery while the other remains available. Both old feature-specific federation stacks and raw remote URL routes were removed; there is no v1 downgrade. No alias namespace. See `docs/federation-protocol.md`. |
| 4 | Web contact privacy and trust | **Implemented and two-server verified.** Account-signed complete manifest history, durable gray-TOFU/green-QR/red-quarantine state, explicit account-incarnation replacement, message requests/blocking, contacts-only libsignal sealed sender, offline-root/online-certificate policy, database-backed abuse limits, anonymous local/federated delivery, capability rotation on block, no identified fallback, and the shared typed XChaCha profile envelope are restart- and two-server-browser verified. |
| 5 | MLS private groups | **V1 binding implemented, activated and two-server verified.** Durable OpenMLS state, manifest-bound devices, private role/control state, quorum-certified multi-authority ordering, owner-approved governance/recovery, destination-private delivery, invitation consent, linked-device sync, restart reconciliation and exact group security inspection use RFC 9420 suite `0x0003` with X25519/ChaCha/Ed25519. The native scale gate operates an actual 256-account × 10-device OpenMLS tree (2,560 independent leaves); the same Rust core builds for WASM, while browser lifecycle, adversarial replay/enumeration, restart/federation and destination-metadata gates pass. Direct and Note to Self remain libsignal. See `docs/chat-mls.md`. |
| 6 | Web messaging and media | **The currently scoped Phase 6 messaging/media slices are implemented: Chat-media is advertised and clean two-server verified; encrypted replies, reactions, author-only edits/deletions, delivery/read receipts, ephemeral typing indicators, disappearing messages, private local search, platform photo/video capture and voice-note recording are present.** Direct, Note-to-Self and MLS attachments use one immutable Rust/WASM-secretstream object, resumable tus upload, sender-free durable federation copies, a dedicated administrator-controlled Chat quota, manual streaming download, clearable encrypted per-conversation accounting and continuous E2EE history/media backup. Browser camera capture uses the browser/OS permission UI and feeds the resulting file into that same encrypted path without a second format, endpoint or plaintext fallback. Voice recording is browser-permission-owned, bounded to 10 minutes and 64 MiB (or the lower server limit), stops every microphone track on all terminal paths, authenticates its duration in the E2EE descriptor and uses the same immutable media path. Replies bind a canonical logical message UUID only inside the shared E2EE content and survive server-hosted backup restore. Reactions are bounded encrypted set/remove operations reduced as one deterministic latest reaction per account without server-visible metadata. Edits use deterministic author-authenticated replacement operations; irreversible deletion tombstones prevent stale-device resurrection. Batched receipt targets and state remain E2EE; read receipts are browser-local opt-in and MLS views aggregate accounts. Typing controls are E2EE, accepted only for established conversations, excluded from product history/transcripts, locally expiring and burst-throttled to limit MLS one-time KeyPackage pressure. Disappearing timers are hidden E2EE controls; every affected text/attachment authenticates its own 30-second-to-30-day duration, senders count from durable creation, and recipients count from first actual view with the earliest absolute start synchronized privately across their linked devices. Durable plaintext and derived controls are atomically purged, unsaved media references are released, and backup restore or browser replacement cannot restart expiry. Local search scans only the decrypted visible browser history, applies edits/deletes/expiry before matching, and never emits a query or plaintext index to a server. The Chat quota defaults to 2 GiB per account and can be increased by administrators. See `docs/chat-media.md` and `docs/chat-protocol.md`. |
| 5b | Confidential broadcast | **V1 blocker scheduled after Phase 6, not an oversized MLS group.** A small MLS owner/admin control group authorizes publishers and the replaceable ordering authorities. A fixed-depth account-leaf LKH serves up to 1,000,000 subscribed accounts; each account access secret is independently wrapped to up to ten manifest devices (10,000,000 grants). Posts are encrypted once and pulled/cached by subscriber homeservers. Removal rekeys before the next post, owner removal performs a restart-safe full rebuild, and history policy is `0..=365` days (default 30) over daily one-way content epochs. See `docs/broadcast-security-threat-model.md`. |
| 7 | Web PWA completion | Generic content-free Web Push, offline/restart recovery, responsive/accessibility/browser matrix, security/load tests, and protocol freeze. |
| 8 | Calls | 1:1 WebRTC → SFU group calls; TURN + SNI demux on 443. Separate from the messaging-complete web milestone. |
| 9 | Native clients | **Work in progress; not release-ready.** Stabilize the UniFFI APIs, package XCFramework/AAR artifacts, complete Keychain/Keystore and lifecycle integration, reach Direct/MLS/media/backup parity, and pass real-device release gates in the sibling iOS/Android repositories. |

Device-list authenticity (the signed per-account device manifest) is **not** in phase 7 — it is a phase-2b/2 wire-contract requirement per the comparative study.

Device continuity is also a **V1 blocker**, not generic PWA polish. Browser
installations are volatile: site-data eviction, private windows, profile
replacement and manual storage clearing all create new cryptographic devices.
V1 exposes active Chat installations and last activity, supports immediate
revocation, and continuously protects display history in an account-local E2EE
server backup. After unified recovery, a replacement browser restores the
verified encrypted base and event tail, then establishes fresh Direct/MLS
protocol state for new messages. The UI reports missing, invalid, offline, or
quota-blocked backup state explicitly. Automated manual-fixture setup must not
publish disposable headless devices unless it retains or revokes them.

#### Phase 6 attachment storage and download decision

The normative protocol and threat model are
[`chat-media.md`](chat-media.md) and
[`chat-media-security-threat-model.md`](chat-media-security-threat-model.md).

Chat attachments reuse Kutup's encrypted Drive/TUS and federation machinery;
they do not introduce a second object-storage stack. The sender uploads an
immutable encrypted attachment and retains a retry/outbox copy until every
destination homeserver has durably accepted it. Each destination homeserver
stores one opaque ciphertext copy, reference-counted for all of its local group
members and devices, so a received attachment remains available if the sender
or sender's server later goes offline. Its logical bytes are reported as Chat
media and count against the recipient's dedicated Chat quota.

V1 uses an administrator-configured dedicated Chat quota, currently 2 GiB by
default, separate from the Drive/general quota. The Chat storage view splits
message history, ordinary delivery media, and protected history media; a future
Photos product receives its own namespace rather than classifying encrypted
MIME data. The same view also shows Chat-media usage per conversation (for
example, `Family group — 842 MiB`) and let the user review or clear that
conversation's stored media. Clearing a recipient's copy releases its quota
and affects that account's linked devices, but never deletes another
participant's copy. The Chat quota is administrator-controlled; there is no
user-adjustable media sub-budget in V1.

Per-conversation accounting must not weaken sealed-sender metadata privacy.
The homeserver stores only the recipient, opaque attachment/reference IDs,
storage namespace and bounded ciphertext byte counts; it does not persist a
sender identity or sender-recipient/chat correlation. The client joins those
opaque IDs to its E2EE message index and computes the named per-chat totals
locally.

The attachment-reference index follows the client-derived encrypted-entity
pattern used by Ente for private user entities and derived file data. Kutup
defines a typed `ChatAttachmentLedgerV1` payload and purpose-specific key, while
reusing the common Rust/WASM envelope, canonical encoding and parser machinery.
The homeserver persists only a suite-bearing encrypted entity, random opaque
entity ID, exact ciphertext size, monotonic account cursor/revision and
tombstone state. It cannot read the conversation ID, message ID, media kind or
display name. Clients fetch bounded cursor pages, decrypt and validate them,
then maintain a disposable local IndexedDB/SQLCipher projection for instant
per-chat totals. A recovered or newly linked device can rebuild that projection
from the encrypted remote ledger without trusting another device to remain
online.

Unlike an unauthenticated last-write-wins blob, ledger updates require exact
previous revision/digest continuity and idempotent operation IDs so concurrent
linked devices cannot silently overwrite one another. The server's separate
opaque byte-accounting rows remain authoritative for quota enforcement; the
encrypted client index is authoritative only for private presentation and
cleanup selection. This shares machinery with other future encrypted account
state without sharing its key or typed payload.

V1 device download is always manual: receiving a message may persist its
encrypted attachment at the homeserver, but no photo, audio, video or file is
downloaded to a recipient device until the user taps **Download**. A message
request carries only the encrypted attachment descriptor; its destination
homeserver must not fetch or allocate storage for the blob before the recipient
accepts the request. This prevents an unauthenticated sender from consuming the
recipient's storage quota.

The V1 protocol ceiling is a 2 GiB plaintext-class attachment plus the exact
bounded overhead of its typed ciphertext framing. Every server defaults to that
ceiling and may advertise a lower local limit, but cannot advertise a larger V1
limit. Admission reserves the exact ciphertext bytes before transfer and
rejects an oversized object before object-storage mutation. The server applies
one media-object limit because MIME type remains encrypted; client recording
and preview code may use smaller type-specific limits.

**Save to Drive** decrypts and re-encrypts the attachment into a visible,
recipient-owned Drive collection charged to Drive/general storage. Clearing the
separate Chat copy releases its Chat charge. Names, captions, thumbnails, MIME details, capabilities and keys
remain inside the E2EE message; servers handle only bounded opaque ciphertext
and public size/accounting fields.

Post-V1 clients may add WhatsApp-style per-user automatic-download policy,
separately for mobile data, Wi-Fi and roaming and separately for photos, audio,
videos and files, with optional size limits. The settings synchronize between
the user's devices through encrypted Note-to-Self state. They control only
device downloads and never weaken the homeserver's durable-storage rule after
an accepted delivery.

### Platform · Advanced traffic-inspection protection [TODO, post-MLS v1]

Add an optional traffic-obfuscation layer for every connection to a Kutup
server and every Kutup server-to-server connection. A shared protected
transport should multiplex Chat, Drive, collaboration, authentication, policy,
identity-manifest, and federation streams instead of creating feature-specific
cover channels. Chat cells carry opaque MLS/anonymous-delivery envelopes;
Drive and collaboration cells carry their existing encrypted requests,
responses, and blob chunks.

This is distinct from sender-metadata minimization and zero-knowledge storage:
fixed-size traffic alone does not hide operation counts, timing, origin
domains, the local authenticated user from their own server, or the recipient
known to its own server. Large Drive transfers also reveal approximate total
size and duration unless bucket padding or correspondingly expensive cover
traffic is enabled.

- Define authenticated, versioned traffic profiles. A required profile never
  silently falls back: unavailable protection queues the message and warns the
  user or pauses the protected operation; weaker transport requires an explicit
  user action.
- Keep **Save mobile data** enabled by default. In this mode use size-bucket
  padding, immediate delivery, opportunistic batching, normal foreground
  connections, and no dummy or constant-rate traffic.
- With **Save mobile data** disabled, use 1,024-byte application cells,
  encrypted bounded fragmentation/reassembly, persistent connections where the
  platform permits, multiplexed batches, dummy cells, and padded
  acknowledgements, errors, authentication exchanges, API responses,
  KeyPackages, MLS control traffic, Drive operations, collaboration updates,
  receipts, and typing events.
- Keep **Hide message timing** disabled by default. When enabled, replace
  scheduled dummy cells with real cells, use a controlled-rate scheduler and
  bounded delay presets, and batch, delay, or disable typing indicators and
  receipts. Urgent security control such as block/device removal may bypass
  artificial delay but must remain padded.
- Allow separate user choices for mobile data and Wi-Fi/Ethernet, synchronize
  them through the MLS Note-to-Self group, and show estimated data use.
- A user may unilaterally send with a stronger profile. Requiring a minimum
  profile needs both users for a direct chat and owner approval plus the group
  ordering quorum for a group.
- Servers advertise supported profiles. Administrators configure global and
  per-feature cell rates, cover-traffic bandwidth budgets, maximum artificial
  delay, padding buckets, large-transfer padding limits, and whether protection
  is offered before login. Server-to-server cover traffic must share one
  authenticated peer channel across features so its cost is amortized.
  Browser/OS background throttling must be surfaced as protection unavailable,
  never treated as permission to downgrade.
- Add strict fragment count, total-size, timeout, replay, deduplication, and
  reassembly-memory bounds. Dummy and real cells must be indistinguishable to
  the passive observer covered by the selected profile.
- Verify packet-size distributions, timing leakage, downgrade behavior, data
  budgets, login/bootstrap behavior, small and large Drive transfers,
  reconnects, background throttling, cross-feature federation batching, and
  adversarial fragment streams before advertising any profile.

---

## New apps (after v1)

Two more apps join Drive and Chat, each built the same way (product owner,
2026-09-26):
- its own origin (`photos.<domain>`, `maps.<domain>`);
- a place in the app switcher;
- one sign-in through session forking, with client types `web-photos` and
  `web-maps`, and `<platform>-photos` / `<platform>-maps` for the native
  apps later;
- the account's one end-to-end encrypted profile;
- federation over the same signed stack.

Each gets a plan in `docs/plans/` before any code. Upstream checkouts for
reference are in `kutup-references/` (`ente`, `comaps`).

### Photos (like Ente Photos)

An end-to-end encrypted photo and video library on `photos.<domain>`.
Plan: docs/plans/photos.md (2026-09-26); slices 1 (the app, the timeline,
the viewer, details read on the device), 2 (favourites, archive, hidden,
Places, editing, trash), 3 (HEIC, RAW, live photos), 4 (private albums) and
5 (albums shared with people here, who may add photos; with people on other
servers, who view them; and public album links) are done. Open: people on
other servers adding their own photos to an album (their photos would live
on their server), and slice 6, tagging on the device.
Reference mostly Ente (`kutup-references/ente`: on-device face grouping,
the Places map, the timeline); Proton's Photos section in its Drive web app
(`kutup-references/WebClients/applications/drive/src/app/photos`, with
albums) is the second reference.
- **Library:** a timeline, albums, favourites, archive and hidden items, and
  trash.
- **Photos are Drive files (decided 2026-09-26):** ordinary files in
  folders you choose, as in Nextcloud Photos and Synology Photos, with
  Drive's encryption (every photo, thumbnail and piece of
  metadata — EXIF, dates, location, captions — under the photo's file key),
  quota, versions, trash and sharing. Uploads and phone backup go to one
  folder you choose (default a normal "Photos" folder in My files); the
  timeline shows that folder plus any other folders you add. The Photos app
  organises them by when and where, not by folder; a photo is one file
  wherever it is and counts once.
- **Albums are views:** an album lists photos without copying them, so one
  photo can be in several albums and still count once.
- **Photo handling:** dates and locations kept per photo (encrypted),
  thumbnails at several sizes, video streaming.
- **Sharing:** one photo with single-file sharing
  (docs/plans/drive-file-sharing.md); albums shared with people here and on
  other servers, collaborative albums, and public album links with the key
  in the URL fragment.
- **Tagging on the device:** faces and people, objects and text found by ML
  models that run in the client (Ente's approach), since the server holds
  only ciphertext; the tags are sealed under each photo's file key and
  synced, and search runs over them on the device. Models run in the
  browser and in the native apps; deferred until after the native iOS and
  Android apps (decided 2026-09-27).
- **Uploads:** from the web; automatic backup from the native apps (with
  mobile, see "Native iOS and Android apps"), into your upload folder.
- **Places:** a map of where your photos were taken, like Ente's, inside the
  Photos app, drawn with the shared map component. Photos cluster by area, and opening a spot shows
  what was taken there. The locations come from the encrypted metadata and
  are placed on the map in the browser, so the server learns nothing.
- **Storage (decided 2026-09-26):** one storage quota per account, shared
  by Drive and Photos, the way one Google One plan covers Google Drive and
  Google Photos; as Drive files, photos use it without anything extra.
  Storage pages in both apps show the shared total. Chat's separate media quota is
  unchanged.
- **Open questions for the plan:** how are live photos, RAW files and
  videos handled (thumbnails and streaming)? How are duplicates found
  without the server learning which files match (a hash kept inside the
  encrypted metadata)? How does the browser keep the timeline of many
  folders fast (a local encrypted index of dates and places), and how do
  albums of photos shared with you work?

### Maps (like CoMaps)

A private map for Chat and Photos, plus lists of pinned places: no tracking,
and your places are yours. It is not a navigation app. Where each part lives
(product owner, 2026-09-26):
1. **Places map, in the Photos app (`photos.`):** where each photo was
   taken. It is part of Photos, not a view in the Maps app.
2. **Pinned place lists, in the Maps app (`maps.`):** end-to-end encrypted lists
   (trips, restaurants, meeting points) that several people edit together,
   shared with people here and on other servers like Drive folders. Your own
   saved pins sync across devices; lists import and export as KML/GPX.
3. **Location, in the Chat app (`chat.`):** sending a place once, and live
   location for a set time, like WhatsApp. Sent, shown and followed inside
   Chat. Both travel end-to-end encrypted inside the chat; a
   live location is a stream of encrypted updates that stops when the time
   runs out or the sender stops it.

Navigation, routing and turn-by-turn directions are not goals. A place can
still be opened in the device's own maps app.

A place is chosen by dropping a pin on the map or taking the device's
current location. City search runs on the device from a downloaded cities
list, as in Ente; searching places by name through a geocoder may come
later.

- **One map component:** a shared package (e.g. `@kutup/map`) that Photos,
  Maps and Chat all use, the way `@kutup/ui` is shared. Each app shows the
  map inside its own pages; none of them sends you to another app to see a
  location.
- **Map data (decided 2026-09-26, docs/plans/maps.md):** no map data on the
  server for now. Tiles come from providers that need no API key
  (OpenFreeMap, OpenStreetMap) or the server's own tile server. The admin
  chooses which are offered and whether traffic goes through a caching proxy
  on the server (off, available or enforced), or turns maps off. Each user
  turns maps on (off by default, with a notice like Ente's) and chooses from
  the admin's list; users cannot add tile servers. Self-hosted map data (the
  CoMaps way) is future work.
- **Privacy:** places, live locations and photo locations stay end-to-end
  encrypted and are drawn in the browser. Loading tiles still reveals the
  area being viewed: directly to the provider, or through the proxy to the
  Kutup server only. With maps off, nothing is requested.
- **Open questions:** in docs/plans/maps.md.

---

## Polish / smaller items (future)

### Chat app (web) follow-ups

Signal feature parity for Chat is tracked in docs/plans/chat-signal-parity.md
(required before deployment).

- **Groups are to be rebuilt.** Group chats (MLS with a federated ordering
  service) proved fragile on the first live server when devices changed, and
  the plan is to rebuild them on an architecture that heals by itself in a
  federation of browsers (see the research report "Self healing encrypted
  group chat"). Until then a server can run without them (`CHAT_GROUPS=false`:
  direct chats only, no group calls), and direct chats get the self-healing
  first: pushed device-list changes, healing on send, undecryptable messages
  as placeholders that fill in, automatic session repair.
- **Networks that block WebSockets: what is left.** Calls get out over TLS
  on port 443 (`turn.` and `sfu-turn.`), Chat reads its mailbox every few
  seconds when its socket cannot open, and a document opens read-only with
  the reason. Not done: live editing over plain HTTPS (a streaming fallback
  for the collaboration hub, for all three editors), and meetings, whose
  signalling (LiveKit) has no transport but WebSockets. Worth building only
  if people are seen behind such gateways.
- **Client-side search and listing index** ([research](research/15-client-side-search-index.md)).
  - Next (Phase 1): an encrypted metadata catalog for the Office home, one
    record per document under a random key wrapped by the account key,
    kept current from a server change feed (an account change log with a
    cursor, or per-folder revisions as a first step) and decrypted into
    worker memory once per session; one tab syncs (Web Lock). Name search
    uses a Turkish-aware fold (İ, I, ı, i → i). Needs the server change feed
    first: today a folder can only be listed whole.
  - Later (Phase 2): full-text search for Chat and notes with SQLite FTS5 in
    the Rust core (SQLCipher natively, `sqlite-wasm-rs` on OPFS on the web)
    and the same fold tokenizer; open questions in the research note.
- **Office home: what is left.** `office.<domain>` lists the notes, office
  documents and whiteboards an account can open and starts new ones in My
  files; they are Drive files and open in Drive's editors. Still open:
  "recent" means last changed, since nothing records when a file was last
  opened; there is no template gallery, only blank documents; a new
  document always goes to My files; files in folders on other servers are
  left out until the editors can open them; a document shows its preview
  only after the editor has saved one.
  The home reads and decrypts every file in every readable folder to find
  the documents among them (as Maps does for its lists), with no limit on
  parallel requests: slow for an account with a very large photo library.
  A server-side query by kind (file kinds are not visible to the server, so
  this needs a sealed index) is the real fix.

- **Direct chats: self-healing.** Worked through in the order of the
  research report "Self healing encrypted group chat" and an audit of the
  direct-chat code against it.
  - Done: a queued message the server will not take no longer keeps the
    mailbox from being read or Chat from opening (it is reported, retried on
    every pass, and holds back only its own conversation); a failed decrypt
    no longer commits a ratchet step without its message; background sync
    failures are caught; a browser whose device was removed elsewhere says
    so and can be set up again instead of "reconnecting" for ever; the
    browser is asked to keep Chat's storage; a send takes no keys from the
    server while it has sessions with the devices it last verified; a
    message that cannot be read repairs its session by itself (reset at most
    once an hour per device, a hidden message hands the sender a fresh
    session) and leaves a notice in the conversation; the server tells an
    account's connected devices when its device list changes
    (`docs/chat-protocol.md`, "Unreadable messages and session repair").
    The message itself is asked for again by id and takes its place when
    it arrives; a contact drops the device list it holds for you when a
    message of yours says your signed list has moved on.
  - Next: signed and last-resort prekeys rotate, and used prekeys are kept
    as long as the mailbox can still hold a message for them. Open edges of
    the re-send: the once-an-hour limits are kept in memory only.
  - Later: writes with strict durability (the IndexedDB wrapper in use
    cannot ask for it; without it a power loss can roll a ratchet back after
    a send); a write generation checked in every transaction and a lock
    timeout, so a second or frozen tab cannot corrupt or stall the engine;
    detection of a restored older snapshot; fault-injection tests (killed
    mid-write, stale snapshot, two tabs).
- **Group device repair: what is left.** A group now recovers when a
  member's only device is replaced (`docs/chat-mls.md`, "Linked devices").
  Still open: it takes up to two minutes (the device check's period), plus
  three per turn if the first member in line is away, during which the
  replaced device sees the group read-only; a non-administrator cannot
  repair a member who lives on another server; messages sent to the account
  before its new device was admitted are lost to that device and linger in
  its mailbox until they expire.
  The server rule and the engine's cross-account path are covered by browser
  tests (38) and TypeScript unit tests, not yet by Rust unit tests.
- **Direct-chat media: what is left.** Attachments, stickers, view-once
  media and voice notes to another person travel by sealed delivery, which
  needs their profile key (it arrives when they accept the message request)
  and a server that offers sealed sender. Where either is missing the attach
  button stays and says why. Still open: a server only offers sealed sender
  once its operator provisions an offline root (`docs/self-hosting.md`,
  "Contacts-only sealed sender"); a server could provision it itself, as it
  does its identity and ordering keys, at the cost of keeping the root on the
  server.
- **Meetings: decisions (2026-10-03).** Recorded here so the next round
  starts from them (`docs/chat-calls.md`, "Meetings", has the design):
  - Conversation calls and meetings stay separate. A one-to-one or group
    call cannot be joined by link, because its key comes from the
    conversation's own encryption; inviting an outsider is done by starting
    a meeting from the conversation, which sends the link there.
  - A meeting's chat is its own and temporary: seen by everyone in the
    meeting, kept nowhere, gone on leaving, not shown to late joiners.
    Keeping it would mean a server-held history, which was not wanted for
    this round.
  - A meeting's time is information, not a lock: the server cannot read
    it, and the link works before and after.
  - Calendar integration is a downloadable `.ics` file and nothing more.
    Mail, Calendar and Contacts are planned as later pieces of Kutup;
    recurring meetings, invitations by email and reminders belong to that
    work and are deliberately not built into Chat.
  - The list of meetings an account joined belongs to the account: sealed
    under its key and stored on its server, so every device shows it. (It
    began as a per-browser list, which was poor to use.) It is its own
    small store rather than hidden Note to Self records, because the
    meeting page that records a stay has no Chat session to send from.
  - The waiting room is optional and off by default, because it needs its
    host present: the owner admits people from inside the meeting, in a
    browser where they are signed in to Chat.
  - Hosts remove and mute people, stop a screen share, lock the meeting
    and let everyone waiting in; the owner names co-hosts and ends the
    meeting for everyone (`docs/chat-calls.md`, "Hosts").
  - Removing someone turns the waiting room on rather than changing the
    meeting's keys: they still hold the link, so the door is what keeps
    them out. Excluding someone for good is a new link for the meeting.
  - A removed person's SFU token cannot be withdrawn, so the server
    remembers removed seats and removes one again when it is back in the
    room. A modified client is in the room for the few seconds that takes
    (the SFU tells the others of a newcomer within about three). Closing
    that entirely would mean moving everyone to a new SFU room on every
    removal, interrupting the meeting each time: not done.
  - Ending a meeting starts a new sitting with its own SFU room, so the
    tokens of the ended one open nothing anyone is in.
  - Each browser's identity in a meeting is bound to a secret it holds (a
    seat), so nobody can take another participant's identity, and a
    co-host is still one after reloading.
  - A meeting left without a host gets one: after 20 seconds the
    longest-present participant becomes a co-host (not the owner).
  - The owner is the host only in a browser where they are signed in to
    Chat; elsewhere they are a guest. Accepted.
  - A signed-in person can show their account in a meeting, vouched for by
    the server; a name alone stays what was typed. Guests have only names.
  - Moderation is for meetings only. Group calls wait for the group work;
    one-to-one calls need none.
  - Admitting people without being in the meeting (from the Meetings page
    or a notification) is deliberately not built: a host lets people in
    from inside the meeting.
  - The meeting routes are rate-limited per network address, so some 25
    people waiting behind one address reach the limit. Accepted for now.
- **Meetings: what is left.** The SFU's webhook for "participant joined",
  to remove a returning removed participant as their media connects rather
  than a few seconds later; an expiry for a meeting; unmuting on request
  ("ask to unmute"); a meeting-wide "only hosts share their screen"; a
  link from another server opening inside the person's own Chat; the
  joined-meetings list pushed to other devices as it changes (it is asked
  for again on focus and every half minute).
- **Meetings with Calendar (after Mail, Calendar and Contacts).** Recurring
  meetings, invitations sent by email, reminders, and picking invitees from
  contacts.

### Files workspace follow-up

The Polar Workspace redesign now provides the responsive Files header,
folder-scoped search, creation menus, folder colors, sorting, selection,
upload progress, drag/drop, contextual empty states, and right-side details
inspector. Future work here is performance measurement for very large folders
and optional filtering/view modes backed by real behavior.

### Drive · office documents and whiteboards across servers

Notes and place lists are edited together live across servers
(docs/plans/collab-federation.md). Office documents and whiteboards from
another server open for viewing and download only, until their editors use
the routed endpoints that notes and lists already use. Deferred (product owner,
2026-09-26) until OnlyOffice is brought into the repo as source we can change.
What it needs, found while starting it:
- **Peer lists across servers.** OnlyOffice drops changes from participants it
  was not told about, and each server's room lists only its own peers. The
  bridge must send its roster home and home must push the merged roster back.
  Entries need a `server` so device ids, which are per server, cannot collide
  (the office bridge keys peers and `indexUser` by device id).
- **Whiteboard images:** `/files/:id/assets/:assetId` relayed like versions.
- Socket, versions, restore and thumbnails taking the remote base, as notes
  do. Also still to come:
shared files in Drive search.

### Office · editor start-up race on reload

On roughly one warm reload in four, ONLYOFFICE's own editor frame loads its
scripts but never reports `onAppReady`, so `api.js` never sends it its
configuration and the loading skeleton stays. The bridge
(`frontend/apps/editor/public/onlyoffice/inner.html`) recovers by mounting the
editor again after 7 seconds, at most twice, so the document opens, but
late. The cause is inside the vendored editor build
(`kutupbt/onlyoffice-editor`); fix it there and drop the watchdog. The office
editing spec (`tests/e2e/specs/03-office-editing.spec.ts`) exercises reloads.

### Chat · MLS changes built on a stale epoch

When an administrator or owner changes a group moments after another
member's commit, before their own client has applied it, both ordering
servers refuse the new block (the local one with 409, a stale height) and
the client shows "Secure chat is temporarily unavailable". It should instead
fetch the control history it is missing, rebuild the change on the current
epoch, and retry. The browser gate
(`tests/e2e/specs/32-chat-two-server-security.spec.ts`) waits for the peer's
commit before acting, as a person usually would.

### Chat · two-server browser gate: sanitized output hides start-up failures

On 2026-10-03 the two-server browser gate failed twice on GitHub's runners
with Chat never showing its navigation after a reload. The cause was the
backup validator refusing a correct record (a device continuing a record
another of the account's devices had moved on; fixed, `docs/chat-backup.md`),
which stops Chat from opening. It took a local reproduction with traces to
see, because the sanitized CI output reports only the test line that timed
out. A start-up outcome in that output (opened, or the failure's class) would
make the next such failure diagnosable from CI alone.

One failure of that day is not explained by the fix: in
`34-chat-backup-two-server-recovery`, a group attachment did not appear in a
restored clean browser within 45 seconds, once in three runs.

### Federation polish

Cross-server presence indicators in collab, outgoing Drive-share revocation,
and federation discovery UX. The common Chat/Drive trust and transport stack is
implemented; these are product-lifecycle improvements above it.

### Test coverage gaps

- Browser-level Drive federation UI coverage (the isolated two-server server
  harness already covers the complete Drive and Chat transport lifecycle)
- Responsive web has an automated phone/desktop axe and state-transition gate;
  physical-device browser coverage and dedicated native-app flows remain open

### Performance baselines

`docs/research/perf-baseline-2026-05-06.md` is a single point. Continuous benchmarking (or even a manual quarterly pass) would catch regressions.

### Desktop app

There is no desktop app for now. The Tauri shell, its desktop release
workflow and the `desktop-v*` tags were removed with the multi-app web
rewrite (it expected the old single app). Desktop returns after the Android
and iOS apps, built against the per-app origins.

### Responsive web · federation share-with from sheet

The mobile share sheet doesn't yet expose federated share flows (cross-server) — only public link sharing.

### CLI follow-ups (from the CLI improvements batch)

The `.excalidraw` whiteboard asset extraction/hydration deferral is **done**
(`crates/kutup-cli/src/whiteboard.rs` — upload extracts + re-snapshots,
download re-inlines; Go-CLI parity reached). What remains around the CLI:

- **Share lifecycle management — done** (docs/plans/drive-share-revocation.md):
  owners list who has access and remove members, federated recipients and
  public links in the web app and with `kutup share access` / `kutup share
  remove`; every removal rotates the folder key. Federated uploads stream
  (signed content digest, spooled and checked before parsing).
- **Server improvements that unlock better CLI behavior** (noted per the
  "do when we touch the server" decision):
  - `latestVersionId` on the `GET /collections/:id/files` rows (one
    `LEFT JOIN LATERAL`) — kills the sync engine's per-file `list_versions`
    polling (its remote-change signal; `files.updated_at` is never bumped).
  - `trashRetentionDays` in `GET /api/auth/settings` — lets `kutup trash ls`
    show an accurate EXPIRES column on any server config (currently omitted
    rather than hardcoding 30).
- **Sync engine: whiteboard assets.** `kutup sync` pushes/pulls `.excalidraw`
  files as opaque bytes; the extract/hydrate steps only run in
  `upload`/`download`. Wire `crate::whiteboard` into the engine's
  push/pull paths.
- **Streaming multipart uploads** for remote `share upload` — still
  buffers the whole encrypted file in memory (`Part::bytes`); switch to
  `Part::reader` with an encrypting reader for large-file parity with tus.
- **`kutup versions restore` vs collab snapshots.** CLI restore re-encrypts
  with the file key in secretstream framing, while web collab snapshots are
  AEAD envelopes under a derived content key — CLI restore round-trips
  CLI/sync-created files, not live-collab documents. Needs the collab
  content-key path if full parity is wanted.
- **`kutup admin` command group.** The full `/api/admin/*` surface (users,
  quotas, stats, activity, settings, 2FA reset, wipe) has no CLI coverage;
  useful for self-hosters. Deliberately deferred from the improvements batch.

### Go→Rust server rewrite · interactive Swagger UI

The Rust `kutup-server` (`crates/kutup-server`)
generates its OpenAPI spec with `utoipa` and serves the machine-readable document at
`GET /api-docs/openapi.json`. The Go server served an **interactive Swagger UI** at
`/swagger/*` (`swaggo/fiber-swagger`). That route is not yet restored in Rust: the
`utoipa-swagger-ui` crate downloads the Swagger UI bundle from GitHub in its build
script, which breaks offline/sandboxed builds (and the rule that the server compiles
offline). Restore it by vendoring the UI bundle (`SWAGGER_UI_OVERWRITE_FOLDER` or a
`file://` `SWAGGER_UI_DOWNLOAD_URL`) so the build stays network-free, then mount it at
`/swagger`. The OpenAPI JSON is unaffected.

---

## Research / open questions

These live in `docs/research/` because the design hasn't been chosen yet:

- **WebDAV mount** — `docs/research/06-webdav-support.md`. Client-side proxy is the only viable path because server-side WebDAV breaks E2EE. Long-term work.
- **WebAuthn / passkey support** — not yet captured in `docs/research/`. Would supplement TOTP for second-factor. Useful research before adding.
- **Chat open questions** — the post-RFC post-quantum MLS suite transition and
  advanced traffic-obfuscation profiles. Direct/MLS retention, continuous
  recovery, and the confidential-broadcast design are already specified or
  implemented; follow the current Chat documents rather than the July research
  baselines.

Collaborative text/Office/whiteboard editing and Drive-style version history
are shipped. Research notes `01`–`08` are retained as the design and debugging
record; they are not open implementation tracks.

---

## Working with this file

- **When something lands**, delete its entry and update the appropriate `docs/*.md` to describe the now-shipped behavior.
- **When you discover a new gap**, add it here. Be specific: file paths, what endpoint, what the user-visible change is.
- **Don't add items that are pure ideas.** Those belong in `docs/research/` as exploratory notes. This file is for committed, scoped work.
- **The `Blockers for v1` section is the gate to the first `v*` tag.** If you're tempted to ship before everything there is done, push back — the user has explicitly asked for production-grade, not fast.
