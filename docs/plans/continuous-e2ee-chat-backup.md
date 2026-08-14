# Continuous E2EE Chat history and backup plan

**Status:** implemented and required-PR-gated; ten-run default-branch rollout
observation pending

**Written:** 2026-08-11

**Scope:** standard Chat display history and eligible Chat media on Web and
Tauri; Direct Chat, Note to Self, and private MLS groups

**Primary reference:** Signal Secure Backups and Signal's media archive
implementation, adapted to Kutup's web-first, federated architecture and
unified account recovery

**Current-state reference:** [`../chat-backup.md`](../chat-backup.md) and
[`../chat-backup-security-threat-model.md`](../chat-backup-security-threat-model.md)

## Completion record

Implementation merged in PR #41 on 2026-08-14. The required zero-retry PR
workflow passed the Rust workspace, Chat core, Rust/WASM/frontend, real
PostgreSQL/SeaweedFS backup lifecycle, single-server clean-browser recovery, and
complete two-server browser-security/recovery jobs. Local hardening also ran the
coordinator crash loop 100 times, server concurrency loop 20 times,
single-server recovery 10 consecutive times, and the two-server matrix 5
consecutive times.

The live federation/browser-loss matrix is therefore complete. The rollout is
not marked fully observed until ten consecutive default-branch CI runs pass
without retry masking, as required by the hardening plan. This file remains the
original detailed implementation design; use the current-state references above
for shipped behavior.

## Original design outcome

Kutup will replace snapshot-cadence Chat backup with an always-on, continuous
encrypted history stream. Each committed, durable Chat display mutation is
added to a crash-safe local backup outbox and uploaded as soon as connectivity
permits. A replacement browser restores one latest encrypted base snapshot and
the ordered encrypted event tail after that snapshot. Media has an independent
encrypted lifecycle and is restored lazily.

Continuous backup becomes the only supported Chat-history restoration
mechanism after rollout. The existing authenticated device-to-device history
transfer is removed from the client, server API, and relay storage. A missing
or invalid server backup follows the explicit history-loss flow; another device
is not offered as a restoration source.

This is an account history feature, not message delivery or protocol-state
backup. A restore can reconstruct what Chat displayed; it can never restore a
libsignal session, an MLS epoch, a device identity, a mailbox cursor, or a
pending send. A recovered installation creates fresh Direct and MLS state for
future communication.

## Locked product decisions

1. E2EE Chat History is always enabled after the existing account-wide Drive
   recovery setup. It uses the same account master key and the same 24-word
   phrase; Chat has no second setup, toggle, consent prompt, or recovery secret.
   An existing account is provisioned by its first backup-capable client after
   account unlock because the homeserver cannot generate its backup root.
2. Backup uses Kutup's existing random account master key and the same 24-word
   recovery path as Drive. It does not introduce a Signal-style backup code or
   a second user-held secret.
3. Backup persists for the lifetime of the account, including while every
   installation is signed out. Complete remote backup deletion occurs only as
   part of account deletion; users free space by deleting Chat messages or
   media while continuous protection remains enabled.
4. A fresh or cleared browser restores encrypted text history automatically
   after account unlock when a valid backup exists. The normal path does not
   offer **Start from scratch**.
5. Restore shows bounded progress, the latest server-acknowledged protected
   timestamp, and incomplete-media state. Text remains usable while media is
   restored on demand.
6. If restore is missing, corrupt, rolled back relative to a local pin, or
   otherwise invalid, show a specific history-loss warning plus retry and
   support actions before revealing **Start from scratch**.
7. **Settings → Chat → Storage** shows the administrator-set Chat quota, total
   usage, message bytes, media bytes, delivery-media bytes, and the
   largest conversations/media known from the client's encrypted index. It
   provides message/media deletion actions, not a backup-disable action.
8. The Chat server-storage quota defaults to 2 GiB per account and is
   configurable by the server administrator. It covers all durable,
   account-owned Chat message-history and media ciphertext, including ordinary
   administrator-retained delivery media and backup media.
9. Device-to-device history transfer is removed. Backup status, restore errors,
   and support flows must not suggest that another installation can supply
   history. When no valid server-hosted E2EE backup exists, the user receives
   the history-loss warning before **Start from scratch** becomes available.
10. Ordinary Chat-media delivery objects expire after an administrator-set
    window (45 days by default). Their
    quota charge is released at expiry; the separately encrypted history-media
    copy remains charged until its message/media reference is deleted. This
    retention change must not ship until eligible media can be copied into
    history and clients can display pending/unprotected media accurately.
11. Backup contains standard Chat only. Reserve a typed protection-domain and
    version boundary for future Vault/locked-chat backup, but do not accept or
    emit locked-chat records in this version.
12. There is one logical latest restore point. V1 has no user-visible backup
    version browser and no server-side plaintext search or inspection.
13. When Chat storage is full, never silently evict older history or media.
    Pause new history/media protection, retain the durable local outbox, and
    ask the user to delete messages or media. Deletion tombstones and compaction
    must remain possible at the quota boundary so the user can actually recover.

## Security and privacy model

### Trust boundary

The account homeserver may store, order, copy, quota, and delete opaque backup
objects. It must not learn a conversation ID, sender, recipient relationship,
message kind, filename, MIME type, reaction, expiry value, or plaintext. A
federated peer never receives an account's backup: backup storage is
account-local at the user's own homeserver even when the archived conversation was
federated.

The client is the only component that can turn live Chat state into backup
plaintext, encrypt it, verify a restore point, or import it. "Continuous" means
near-real-time client uploads; it does not mean that a homeserver can create
backup events while no usable client is running. A message received while all
usable installations are offline enters backup only after a client capable of
decrypting it receives and commits it.

An attacker who obtains the account master key can open the wrapped backup root
and therefore the archive. That matches the existing unified recovery promise.
Backup does not expand a homeserver compromise into plaintext access, and no
backup key may be logged, placed in metrics, or sent as an ordinary server
field.

### Rollback boundary

Every existing installation pins the highest valid backup generation, account
cursor, and manifest digest it has observed. It rejects a lower generation,
lower covered cursor, conflicting digest, broken generation hash chain, or
manifest signed by an unauthorized key.

A completely fresh installation has no independent local pin. In V1, a
malicious homeserver can replay an internally valid old backup to that device.
The account signature proves origin and integrity, not freshness in the absence
of an external witness. Eliminating this residual risk requires an external
witness/transparency service or a Signal-style secure-enclave freshness
service; neither is implied or claimed by V1.

## Cryptographic hierarchy and formats

### Root and typed envelope

At unified recovery setup, or at the first backup-capable account unlock for an
existing account, the client generates a fresh random 32-byte
`ChatBackupRootV1`. It wraps that exact value with `AccountEnvelopeV1` under the
account master key using a new closed `AccountEnvelopePurpose::ChatBackupRoot`.
The existing envelope authenticates suite, purpose, canonical account context,
nonce, and exact length. A Drive private-key envelope, password/recovery
master-key envelope, or envelope for another account must not open as a backup root.

A destructive account reset or account recreation creates a new root and a new
backup incarnation. The server must not attach objects from an erased
incarnation to the new one, even when account, device IDs, or opaque operation
IDs collide.

### Suite registry and derivation

Add a purpose-specific `ChatBackupSuiteId`. It is independent from
`DirectChatSuiteId`, `MlsCipherSuiteId`, `ChatMediaSuiteId`,
`ChatAttachmentLedgerSuiteId`, Drive suites, and history-transfer framing.
Unknown suites fail closed and never trigger an in-band downgrade.

V1 uses the existing Kutup primitive portfolio: SHA-256, HKDF-SHA256,
XChaCha20-Poly1305, libsodium-compatible secretstream where streaming is
required, and the existing account-authority signature profile. All KDF
labels include a terminal NUL in the canonical byte domain, as do existing
Kutup protocol labels.

Derive independent subkeys from `ChatBackupRootV1`; never use the root directly
as an encryption key:

| Purpose | Fixed HKDF info label |
|---|---|
| Base message archive | `kutup/chat-backup/message-archive-key/v1` |
| Event segments | `kutup/chat-backup/event-segment-key/v1` |
| Opaque media IDs | `kutup/chat-backup/media-id-key/v1` |
| Backup-media outer encryption | `kutup/chat-backup/media-encryption-root/v1` |
| Manifest signing | `kutup/chat-backup/manifest-signing-seed/v1` |

The derivation context binds `ChatBackupSuiteId`, canonical account,
authenticated account incarnation, backup incarnation, and protection domain.
Per-segment keys additionally bind source device ID, device sequence, random
operation ID, and previous segment digest. Per-media keys bind the derived
opaque media ID, source ciphertext digest, exact padded length, and media
format version. A nonce or per-object key is never reused.

The derived manifest signing public key is authorized by the existing account
authority for the exact backup incarnation. Canonical manifests are signed by
the authorized backup signer and carry that account-authority authorization.
This retains a purpose-separated online backup key while anchoring every
generation in the existing recoverable account identity. The exact
authorization and manifest bytes, including hash-chain fields, are frozen in
`kutup-chat-proto` and covered by Rust/WASM vectors before storage work begins.

### Protection domains

Every header includes a closed protection-domain field:

- `1`: standard Chat;
- all other values: rejected in V1.

Future Vault/locked-chat support must allocate a distinct domain, keys,
eligibility policy, user consent, and restore UI. Merely changing a record kind
inside the standard archive is forbidden.

## Backup record model

### Stable record identity

Add stable backup record IDs for locally live Direct/Note-to-Self history, MLS
history, and already imported display history. IDs are generated or normalized
at the durable Chat commit boundary and remain stable across edits, reactions,
delivery-state changes, compaction, restore, and a later backup export.

Imported rows require a backup provenance ID independent of their one-time
history-transfer UUID so re-backing up a restored/imported row remains
idempotent. Record IDs are opaque to the server and are carried only inside
encrypted archive frames.

### Included display state

Back up the normalized state needed to reproduce the visible conversation:

- messages and replies;
- author-authenticated edits;
- deterministic one-reaction-per-user set/remove state;
- delete tombstones and local deletion state where product semantics require
  it;
- delivered/read presentation state without transport cursors;
- conversation settings and disappearing-message timer controls;
- absolute recipient first-read expiry, so restore cannot restart a timer;
- attachment descriptors, embedded encrypted previews, and opaque backup-media
  locators; and
- provenance/version fields required for deterministic reduction and import.

Events express mutations, but a compacted base contains their normalized
latest logical display state plus all tombstones and expiry facts still needed
to prevent resurrection.

### Excluded state

Never place any of the following in a backup plaintext frame, staging record,
or media descriptor:

- libsignal sessions, ratchets, sender keys, or PQXDH material;
- MLS epoch secrets, KeyPackages, Welcome secrets, provider snapshots, group
  private state, or active epoch state;
- device identity/private keys, account private keys, signed prekeys, one-time
  prekeys, or registration material;
- mailbox cursors, receipt cursors, delivery capabilities, retrieval bearer
  state, federation retries, or replay reservations;
- pending send/sync outboxes, pending inbound journals, draft messages, typing
  state, or local search indexes; or
- plaintext media, filenames, MIME types, conversation identifiers, or sender
  identities outside encrypted frames.

### Eligibility and deletion ordering

Exclude view-once content, already expired content, and content whose absolute
expiry is within 24 hours at the time the backup event is created. A record
that becomes ineligible later produces a tombstone/removal event; compaction
must not retain its plaintext.

Persist and enqueue an irreversible backup tombstone in the same logical
mutation transaction before deleting the local display row. Local removal must
not complete if it would leave no durable tombstone/outbox fact. This ordering
prevents another device or an older base from resurrecting deleted or expired
content.

### Restore isolation

Restore decrypts and validates the complete selected base plus tail before any
plaintext import. It then imports through the existing normalized history
importer into the isolated `imported_history` display store. Restore must not:

- advance a mailbox cursor;
- acknowledge or delete an inbound envelope;
- establish or modify a libsignal session;
- import an OpenMLS provider snapshot or change an MLS epoch;
- emit delivery/read receipts or linked-device sync;
- enqueue an outbound message; or
- make restored content eligible as evidence of a live cryptographic session.

After display import, new Direct or MLS communication follows the ordinary
fresh-device/session recovery path. Restored display rows and live rows reduce
by stable record ID so duplicates do not appear when recent mailbox delivery
overlaps the backup tail.

## Continuous event upload

### Atomic local outbox

After each committed durable Chat mutation, create its canonical backup event,
encrypt it, and queue it durably in the same Chat-core transaction where the
platform store permits. IndexedDB and SQLite use equivalent restart-safe
semantics. A mutation is not reported as protected merely because local
encryption succeeded.

Outbox records contain only the encrypted segment material and opaque protocol
metadata needed for upload. They survive reload, process termination, offline
periods, token refresh, and ordinary sign-out. They are scoped to account and
backup incarnation and are purged only after exact server acknowledgement or
account deletion.

Flush automatically:

- after a short debounce following a committed mutation;
- when an encrypted batch reaches 64 KiB;
- when the document becomes hidden, using a bounded best-effort request;
- when the client regains connectivity; and
- on the next startup whenever acknowledged work remains incomplete.

### Segment append contract

Each immutable encrypted append carries:

- random idempotency operation ID;
- source device ID and monotonically increasing per-device sequence;
- previous acknowledged segment digest for that source-device chain;
- account-manifest sequence used to authorize the source device;
- backup incarnation, protection domain, and suite;
- exact ciphertext size and SHA-256 digest; and
- encrypted segment header/body with a final authenticated frame.

The homeserver verifies only public bounds, account/device authorization,
idempotency consistency, sequence continuity, digest continuity, quota, and
format headers. It assigns a monotonic account backup cursor at commit. It
learns no conversation, sender, content kind, filename, or plaintext timestamp.

An exact retry returns the original acknowledgement. Reusing an operation ID
with different bytes or bindings is a terminal conflict. Concurrent devices
append independently; a stale account cursor causes a bounded refetch/retry,
not replacement of another device's acknowledged events. Ordering for restore
is the server-assigned account cursor, with source-device sequence and digest
chains verified as integrity constraints.

### User-visible status

Status is driven by durable server acknowledgement and media state:

| Status | Meaning |
|---|---|
| `Protected` | All eligible message events are acknowledged and no required media is pending |
| `Backing up` | Message encryption/upload or acknowledgement is in progress |
| `Offline` | Durable local work is pending and the homeserver is unreachable |
| `Media pending` | Message archive is current but eligible media awaits copy/upload |
| `Storage full` | Protection is paused; show the latest protected time and actions to delete Chat data or increase/request quota |
| `Backup needs attention` | No new valid restore point can be published or validation/authentication has failed |

The displayed **Latest protected** timestamp is the greatest eligible Chat
mutation covered by the acknowledged logical restore point, never the local
encryption time or last upload attempt.

## Restore point and compaction

### Logical shape

The only user-visible restore point consists of:

```text
signed manifest
  ├── one encrypted base snapshot covering account cursor C
  └── every ordered, acknowledged encrypted segment in (C, current cursor]
```

The manifest commits to backup/account incarnation, suite, protection domain,
generation, previous manifest digest, base object ID/digest/length, covered
cursor, media-reference-set digest, signer authorization, and creation time.
The CAS request separately supplies the exact current account cursor and prior
manifest digest it expects. New immutable appends extend the tail without
replacing that base manifest. Exact canonical types reject unknown keys and
noncanonical encodings.

### Trigger and algorithm

Compaction is maintenance, not the backup cadence. Attempt it while a client is
active when the tail exceeds either 10,000 events or 64 MiB of encrypted
segments. Give an eligible active client one daily opportunity as a fallback,
but do not compact an unchanged empty tail merely because a day elapsed.

A compactor must:

1. Fetch the exact current signed manifest, base, and complete ordered tail.
2. Verify account authorization, generation chain, local rollback pin, every
   public digest/length, every source-device sequence chain, all ciphertext
   authentication, archive bounds, expiry, and canonical plaintext.
3. Deterministically reduce records, tombstones, edits, reactions, settings,
   delivery state, and expiry into a new normalized base.
4. Build the complete referenced-media set and its digest.
5. Encrypt and upload a staged replacement base without altering the current
   restore point.
6. Download the staged object and validate it client-side, including a bounded
   decrypt/parse pass and expected logical digest.
7. Compare-and-swap the manifest against the exact current generation, cursor,
   and manifest digest.
8. Pin the committed generation/cursor/digest locally, then permit asynchronous
   garbage collection of superseded objects.

A CAS conflict discards or reuses only the caller's uncommitted staging object,
refetches the winner, and retries from the new complete base plus tail. It never
overwrites an acknowledged concurrent segment. The old base remains readable
until the new base is uploaded, validated, and committed atomically.

If compaction or the Chat quota fails, retain the last valid manifest and all
objects it references. Never publish a partial base or a manifest with a
missing tail.

## Media backup

### Eligible copy model

Back up every eligible attachment whose verified Chat-media ciphertext is
available to the client or its homeserver, subject to the dedicated Chat
server-storage quota.
The encrypted message descriptor carries the source binding and resulting
opaque backup-media locator. Embedded previews remain inside the message
archive; do not create a second preview object.

Derive an opaque media ID with the media-ID key over the complete stable source
binding. Derive a distinct per-media outer encryption key from the media
encryption root and that opaque ID. The media ID reveals no message,
conversation, sender, filename, MIME type, or original attachment ID.

Follow Signal's efficient copy shape:

1. The client authorizes a copy of an already E2EE Chat-media ciphertext.
2. The homeserver reads that opaque ciphertext without decrypting it.
3. The source ciphertext is padded to 1.05-growth buckets with a 541-byte
   minimum.
4. The homeserver wraps the padded source ciphertext in backup-specific outer
   encryption and stores it in the backup-media namespace.
5. The client verifies the resulting object binding, digest, and exact length
   before marking the media protected.

The per-item outer key may be supplied to the narrowly scoped copy operation.
The original attachment plaintext and original attachment key never reach the
server. Possession of a copy-operation key must not authorize another media ID,
another backup incarnation, archive reads, or manifest commits.

If the ordinary delivery object has expired but an authorized client
retains a locally verified encrypted copy, allow a direct encrypted backup
upload using the same backup-media format and final verification. Never
decrypt/re-encrypt the inner attachment merely to upload it.

### Lazy restore and absence

Text restore resolves only backup-media locators and availability metadata. On
open, the client fetches, verifies, removes backup padding, opens the outer
layer, and then processes the original Chat-media ciphertext with its original
E2EE descriptor. It may cache the verified encrypted result under the separate
local-media-cache policy.

One missing, corrupt, quota-pending, or deleted media object does not invalidate
otherwise authenticated text history. The attachment renders a specific
unavailable/pending state and can be retried or reconciled without reimporting
the archive.

## Quota, retention, and reconciliation

### Dedicated Chat storage quota

Add `chatStorageQuotaBytes` and the following authenticated usage categories:

- `chatMessageBytes`: encrypted base/tail history and other durable
  account-owned message ciphertext;
- `chatDeliveryMediaBytes`: ordinary media copies within their administrator-set delivery
  lifetime; and
- `chatHistoryMediaBytes`: media protected for continuous history restore.

Their sum is the user's Chat storage usage. These are byte-accounting
categories, not plaintext classifications inferred by the server. Drive and
other products do not consume the Chat quota, and Chat does not spill into
their quota.

The default is exactly 2 GiB (`2 * 1024 * 1024 * 1024` bytes) per account. The
server administrator can change the instance default and set a per-account
override. Server capabilities and every authenticated storage response report
the exact byte limit; clients never hard-code 2 GiB as an immutable protocol
ceiling.

Lowering a quota below current use preserves all existing valid history and
media, marks the account `Storage full`, and blocks new charged commits until
usage falls below the new limit. It never deletes data. Raising the quota wakes
pending work automatically.

Reservations, object/reference commits, idempotency receipts, and quota changes
are transactional. One logical object is charged once per account/category.
Where an ordinary delivery-media object and a history-media copy coexist during
the delivery-retention window, both physical ciphertext copies are charged; delivery expiry
then releases only the delivery charge.

An account is charged once for each message/media object retained for that
account, whether the conversation is Direct or MLS and whether the other party
is local or federated. Server-side physical deduplication or reference counting
does not reduce a user's logical charge or couple one participant's deletion to
another participant's copy.

### Full-quota behavior

When a new message-history segment or media object cannot fit:

1. Garbage-collect unreferenced objects and abandoned staging that are not part
   of the latest valid restore point.
2. Preserve the current valid restore point and every media object it
   references. Never prefer newer content by evicting older protected content.
3. Keep new message events and eligible media as explicit durable local pending
   work. New text may remain usable locally, but **Latest protected** does not
   advance beyond the acknowledged server cursor. New media upload/send may be
   blocked when it requires server storage.
4. Show **Latest protected** with its exact date/time, exact usage/limit, and
   pending message/media counts and bytes. Present persistent **Review and
   delete** and **Increase storage** actions.
5. Let the client use its encrypted index to offer deletion by conversation,
   age, or large media without revealing those groupings to the server.
6. Route **Increase storage** to an advertised self-service quota/plan flow when
   available; otherwise label it **Request more storage** and show how to
   contact the server administrator. The client cannot raise its own quota.
7. Persist deletion tombstones before local removal, commit reference removal,
   compact, and then resume pending work automatically when space is available.

Quota enforcement must leave bounded internal headroom for tombstones,
reference removals, and compaction metadata. Replacement compaction staging is
not double-billed as new logical user history while the old valid base is still
required for atomic CAS, although the server must budget physical temporary
storage and enforce strict staging bounds. Without this rule, a completely full
archive could not process the deletion needed to recover.

Do not publish a partial message archive or claim that locally queued work is
protected. If the last device holding pending work is cleared before quota is
freed and the server acknowledges it, that unprotected tail can be lost; the
full-storage UI must state this plainly.

### Deletion and retention

- Ordinary Chat-media delivery copies expire after the administrator-set window, subject to
  disappearing-message or explicit deletion happening sooner.
- Backup media survives delivery expiry while referenced by the latest logical
  restore point.
- A message tombstone/expiry removes its backup-media reference on the next
  valid logical restore point; unreferenced media is then garbage-collected.
- Account deletion releases every Chat message/media object, root envelope,
  manifest, segment, reference, receipt, staging object, and quota row
  transactionally and remains safe to retry.
- Periodic reconciliation covers delivery-retention purge, account deletion,
  abandoned staging uploads, dangling references, missing objects, and exact
  quota repair without deriving private conversation relationships.

## Versioned client and server interfaces

Exact DTOs belong in `kutup-chat-proto`, use `deny_unknown_fields`, canonical
base64/hex/UUID rules, explicit byte ceilings, and OpenAPI coverage. Names below
describe the required resource split; final paths should follow existing
`/api/chat` routing conventions.

| Operation | Required behavior |
|---|---|
| Provision history | Idempotently create the account's required backup incarnation with root envelope, signer authorization, suite/domain, and account binding |
| Get backup status | Return provisioning/protection state, exact advertised limits/suites, current opaque manifest, cursor, acknowledged bytes, and Chat quota categories |
| Append event segment | Idempotent immutable append with device/account sequence checks and server cursor assignment |
| Upload/download base | Stage or stream exact opaque base bytes with length/digest verification; current base changes only through manifest CAS |
| Commit manifest CAS | Compare exact generation, cursor, and prior digest; atomically publish base/tail/media reference set |
| Copy backup media | Authorize server-side inner-ciphertext copy plus backup-specific padding/encryption |
| Upload backup media | Directly stream a verified local encrypted source copy into the same outer format |
| Resolve/download media | Return only an authenticated opaque object for a locator in the current backup incarnation |
| Reconcile media | Page through opaque current/staged/referenced media state with stable cursors and bounded pages |
| Delete account history | Account-deletion-only, idempotent erasure of the exact backup incarnation and all Chat accounting state |

The server capability document advertises exact suite IDs, maximum segment/base
sizes, page limits, compaction thresholds, padding profile, default/effective
Chat quota, live-media retention, and feature availability. Older clients ignore unknown
backup capability fields and preserve existing Chat behavior. A server must not
advertise backup until local object storage, deletion, quota, reconciliation,
and restore downloads are all configured.

Extend the Chat client service with:

- automatic provisioning, status, storage-management, and account-deletion
  cleanup operations;
- mutation-to-record normalization and eligibility filtering;
- durable outbox state, flush, retry, and acknowledgement;
- compaction scheduling and CAS commit;
- restore discovery, verification, import, progress, and cancellation;
- media copy/upload queue and lazy resolution; and
- a single observable status model for Settings and setup flows.

## Server persistence model

Add migrations for logically separate state; do not overload the existing
history-transfer relay or Chat-media attachment ledger:

- account backup provisioning state, backup incarnation, suite/domain, root
  envelope, signer authorization, current cursor, and current manifest digest;
- immutable signed manifest generations and current base pointer;
- ordered encrypted segments with account cursor, source-device chain,
  operation receipt, size, and digest;
- staged and committed base objects;
- backup media objects, latest-restore-point references, padding profile,
  source-copy authorization state, and availability;
- idempotency receipts and bounded staging-upload leases; and
- `chat_message`, `chat_delivery_media`, and `chat_history_media` quota
  categories plus the effective administrator-set Chat quota.

Database rows may contain account ownership, opaque IDs, suite/domain, public
format bounds, digests, byte counts, cursors, device IDs, lifecycle state, and
timestamps required for operations. They must not contain decrypted record
metadata, original filenames/MIME types, conversation/sender fields, or
server-derived media classifications.

## Restore and settings experience

### Automatic provisioning

Unified recovery setup automatically performs Chat backup key generation,
envelope upload, initial normalized snapshot, media queue creation, client-side
verification, and first manifest commit. Existing accounts perform the same
idempotent provisioning at their first backup-capable account unlock. The UI
explains that Chat history uses the existing recovery phrase and the
administrator-set Chat storage quota; it does not ask the user to enable it.

Closing the browser during provisioning leaves a restart-safe staging/outbox
state. The server reports `Provisioning`, not a usable backup, until the first
complete manifest is committed.

### Fresh-browser restore

After account unlock:

1. Discover enabled backup status and the latest signed manifest.
2. Unlock the backup root from its typed envelope.
3. Fetch and verify the base and complete tail with bounded progress.
4. Import normalized display records atomically into isolated history storage.
5. Render Chat while media remains lazy and continue ordinary fresh-device
   Direct/MLS initialization independently.
6. Show **Latest protected**, any acknowledged gap, and pending-media state.

Do not show an empty conversation list while restore is silently pending. Do
not ask whether to discard a valid archive. If retryable transport fails, keep
retry available. If validation fails, preserve the encrypted failure evidence
needed for support without logging plaintext, and do not partially import.

### Storage management

Settings shows the effective Chat quota, total usage, the three server
categories, pending/unprotected bytes, and **Latest protected** date/time. Using
the client's decrypted index, **Review and delete** can group usage by
conversation, age, and large media without sending those labels to the server.
It also shows **Increase storage** for an advertised self-service flow or
**Request more storage** with administrator guidance. Only the server's quota
administration can change the effective limit.

Deletion uses existing message/media semantics, including author permissions,
local-only versus delete-for-everyone behavior, tombstones, disappearing
expiry, and attachment reference removal. The UI shows `Reclaiming space`
until the server acknowledges deletion and any required compaction releases the
charge. There is no disable-and-delete control. Complete remote erasure is part
of the existing re-authenticated account-deletion flow.

## Implementation sequence and acceptance gates

Each slice is independently reviewable. Protocol constants and deletion
semantics must be frozen before UI claims the feature is protective.

### Slice 1 — Threat model, canonical formats, and vectors

- Add the backup threat-model document, typed suite/purpose/domain registries,
  key hierarchy, headers, canonical archive events, manifest/signatures,
  padding rules, and strict bounds.
- Define stable IDs and normalization rules for Direct, MLS, and imported
  history.
- Add deterministic cross-language vectors and adversarial parser fixtures.
- Record the fresh-device rollback limitation explicitly in the threat model
  and user/support documentation.

**Gate:** Rust, WASM, and TypeScript fixtures agree byte-for-byte; wrong purpose,
context, suite, generation, nonce, length, and signature fail closed before
server persistence work begins.

### Slice 2 — Server storage, CAS, Chat quota, and deletion

- Add migrations and object namespaces for roots, segments, bases, manifests,
  media, receipts, staging, and quota.
- Implement provisioning/status, immutable append, base streaming, manifest
  CAS, the administrator-configurable 2 GiB default Chat quota, deletion
  headroom, exact quota transactions, account-deletion cleanup, and
  reconciliation.
- Advertise capability only in test deployments until restore is present.

**Gate:** opaque-object API tests cover conflicts, retries, concurrent devices,
full and admin-lowered quotas, deletion at the quota boundary, crash-left
staging, account deletion, and exact quota release without a plaintext Chat
field in storage/logs.

### Slice 3 — Normalized collection and isolated import

- Reuse the existing history-transfer collector/importer and
  `imported_history` isolation boundary.
- Extend normalized records for stable backup IDs, tombstones, edits,
  reactions, settings, expiry facts, attachment locators, and imported-history
  provenance.
- Enforce exclusion and 24-hour eligibility rules at collection and restore.

**Gate:** a fixture containing Direct, MLS, and imported rows round-trips its
visible state without importing any ratchet, MLS, mailbox, receipt, or outbox
state; deletion and expiry cannot resurrect.

### Slice 4 — Continuous outbox, append, restore, and compaction

- Add IndexedDB/SQLite backup outbox stores in Chat core and atomic hooks for
  every durable visible mutation.
- Implement debounce/64 KiB/hidden/startup flush triggers, acknowledgement
  status, per-device chains, concurrent append retry, full restore, pins, and
  compaction CAS.
- Make crash points deterministic and resumable.

**Gate:** two devices append concurrently; interrupted uploads and reloads
resume; compaction can crash at every stage without losing the old restore
point; a fresh store reconstructs identical base-plus-tail display history.

### Slice 5 — Backup media and live-media retention

- Implement opaque media IDs, derived outer keys, 1.05 padding with 541-byte
  minimum, server-side encrypted copy, direct encrypted upload, lazy restore,
  pending queue, and paginated reconciliation.
- Add configurable live Chat-media expiry only after copy/pending behavior is usable.
- Connect message-reference removal to backup-media garbage collection without
  evicting still-protected objects.

**Gate:** a live delivery object expires after the configured window while its history copy
remains lazily restorable; both are charged during their overlap and the live
charge is released at expiry; direct upload recovers from a verified local
encrypted copy; exact deletion/reconciliation accounting passes.

### Slice 6 — Product flows and destructive controls

- Add automatic provisioning, Settings status/usage, fresh-browser automatic
  restore, progress, pending-media/full/attention states, retry/support paths,
  and encrypted-index-driven **Review and delete** actions.
- Remove every device-transfer entry point. While a usable backup exists,
  normal setup also omits start-from-scratch; when no valid backup exists, it
  uses the explicit history-loss flow.
- Preserve accessibility, mobile safe areas, keyboard/focus behavior, and
  truthful offline semantics.

**Gate:** setup, restore, failure, quota, offline, and deletion UX tests pass;
backup cannot be disabled, a full account can reclaim space, and account
deletion removes remote history without leaving charged objects.

### Slice 7 — Remove device transfer and complete rollout

- Remove device-to-device history-transfer UI, client orchestration, transport
  methods, server routes, relay persistence, staging frames, and capability
  advertisement.
- Preserve already imported display-history rows and reuse normalization/import
  code where useful; removal of the transport must not delete local history.
- Remove or migrate crash-left transfer journals and server relay frames
  without touching continuous-backup state.
- Run the full browser-loss, sign-out, retention, and federation matrix before
  making server-hosted backup the only restoration path.

**Gate:** no setup, Settings, recovery, client API, advertised capability, or
server route can initiate device-to-device history transfer. Missing or invalid
backup reaches the explicit history-loss flow without deleting local history.

## Verification matrix

### Cryptographic and format tests

- Rust/WASM vectors for every KDF label, account envelope, root/suite/domain,
  event segment, base snapshot, manifest authorization/signature/hash chain,
  media ID, outer media object, and padding bucket.
- Reject wrong purpose, account, account incarnation, backup incarnation,
  protection domain, suite, device sequence, cursor, digest, nonce, exact
  length, generation, previous-manifest digest, media ID, and final tag.
- Reject noncanonical encoding, unknown fields, truncation, trailing bytes,
  duplicate final frames, ciphertext substitution, and cross-object relocation.
- Bound decompression ratio, decoded bytes, record counts, nesting, string
  lengths, event batches, and media padding before allocation; reject
  compression bombs before plaintext import.

### State-machine and adversarial tests

- Two devices append concurrently without overwriting each other.
- Exact idempotent retry returns the same cursor; changed retry conflicts.
- Offline mutation, interrupted upload, token refresh, hidden-page flush,
  browser reload, and process restart preserve queued work.
- Reject duplicate events, source-device replay, reordered/missing tail,
  rollback below a local pin, conflicting manifest, and incomplete base.
- Crash compaction before upload, during validation, before/after CAS, and
  during old-object collection; one complete restore point always survives.
- Edits, one-reaction-per-user changes, deletes, message expiry, and absolute
  read expiry reduce identically before and after compaction and never
  resurrect from an older base.
- View-once, ratchets, MLS secrets/state, device keys, mailbox state, search
  indexes, delivery capabilities, and pending outboxes never enter an archive.
- Restore failure occurs before any plaintext import; successful restore emits
  no receipt, cursor advance, send, session establishment, or MLS mutation.

### Quota, lifecycle, and deletion tests

- Verify the exact 2 GiB default, administrator-set instance default,
  per-account override, and independence from Drive quota.
- Lowering the Chat quota below usage preserves the last valid restore point,
  reports `Storage full`, and never evicts data.
- Full state preserves old messages/media, durably queues new eligible work,
  reports **Latest protected** plus exact pending count/bytes, offers deletion
  and increase/request-quota actions, and retries after space is freed.
- Deletion tombstones, reference removal, and compaction succeed at the quota
  boundary; replacement staging is bounded and not double-billed.
- Reconciliation repairs leaked reservations/staging and exact message/media
  usage without deleting referenced objects.
- A delivery-media purge releases its charge while history media remains
  available; early disappearing/delete expiry still wins.
- Account deletion removes every base, segment, media copy, envelope, manifest,
  receipt, stage, reference, and quota row and is idempotent across crash/retry.

### Browser and federation end-to-end gate

Use Alice on `a.test` and Bob on `b.test`:

1. Complete unified recovery setup and verify history is provisioned
   automatically for both accounts with the server-advertised Chat quota.
2. Exchange Direct and MLS messages, replies, media, reactions, edits,
   delivery/read state, deletes, and disappearing messages from two devices
   each.
3. Verify concurrent continuous appends, acknowledged status, offline queueing,
   reload resume, media copy, and compaction.
4. Sign out every device and clear both browser stores.
5. Recover each account using its existing Kutup recovery path in fresh
   browsers; restore base plus complete event tail automatically.
6. Confirm visible state, tombstones, absolute expiry, settings, status, and
   latest protected time; inspect that no restore advanced a mailbox or reused
   Direct/MLS secrets.
7. Open backed-up media lazily, including after ordinary delivery copies
   are purged, and verify text remains usable when selected media is absent.
8. Establish fresh Direct/MLS state and exchange new messages after restore;
   ensure overlapping delivery and restored records deduplicate by stable ID.
9. Fill the Chat quota, confirm old protected messages/media are not evicted,
   new work is reported as pending/unprotected, delete selected messages/media,
   and verify compaction frees space and pending work resumes.
10. Lower one account's administrator-set quota below current use, verify
    read-preserving full state, then delete the account through re-authentication
    and confirm all remote Chat state/quota is gone.
11. Make the other backup unavailable and verify that no device-transfer action
    or API is offered; retry/support precede the explicit history-loss warning
    and **Start from scratch** action.
12. Inspect both homeservers' database rows, object paths, logs, metrics, audit
    events, and federation traffic for forbidden plaintext or backup leakage.

## Documentation and rollout

Before advertising this feature:

- add the normative Chat-backup protocol and threat-model documents;
- update `docs/architecture.md`, `docs/api.md`, `docs/chat-protocol.md`,
  `docs/chat-media.md`, both Chat media/security threat models, the V1 format
  inventory, self-hosting retention/quota guidance, and `docs/roadmap.md`;
- explain that the 24-word phrase recovers Drive and opted-in Chat history, but
  that a server can replay an old archive to a completely fresh V1 device;
- document the administrator-configurable 2 GiB default Chat quota, full-state
  and deletion-headroom behavior, media padding, configurable delivery-media
  retention, reconciliation, support diagnostics, and account deletion;
- capability-gate every server/client write path and keep older clients on
  existing Chat behavior; and
- deploy storage/CAS/reconciliation dark, then continuous message backup, then
  media copy, then automatic restore, and only then change ordinary media
  retention and remove device-to-device transfer.

During rollout, an account is never considered protected unless its server has
acknowledged a complete valid logical restore point. Telemetry and logs use only
aggregate error codes, byte counts, and durations; they do not include object
digests, media IDs, record IDs, account keys, filenames, conversations, or
plaintext timestamps.

## Deferred portable backup file

A later release may add **Download encrypted backup file** for provider
independence and user-controlled archival. It is not part of the initial
server-hosted restore mechanism and must not delay or complicate that rollout.

Treat portable export/import as its own versioned format and threat-model
change. Before shipping it:

- define and test the matching import flow; do not offer an export that Kutup
  cannot restore;
- make the file self-contained enough to restore without the original
  homeserver, while retaining the existing 24-word recovery model and never
  adding an unencrypted key;
- require recovery-phrase verification before creating any new portable key
  wrap, and do not include password-derived material that enables offline
  password guessing;
- stream export and import with bounded memory, exact lengths/digests, final
  authentication, cancellation, and partial-file rejection;
- decide whether media is embedded, split into authenticated volumes, or
  intentionally omitted, and show that choice and exact sizes before export;
- preserve tombstones, absolute disappearing-message expiry, stable record
  IDs, suite/domain separation, and the same isolated display-history import
  boundary as server restore;
- provide explicit file-safety and storage guidance because anyone holding the
  file plus the recovery phrase can recover its history; and
- add rollback/age warnings for importing an older portable file over newer
  local or server-hosted history.

The portable file is not a replacement for continuous protection: Kutup cannot
update a downloaded file after it leaves the application. It is a deliberate
point-in-time export and manual recovery source.

## Explicit non-goals

- Backing up or restoring libsignal, MLS, device, mailbox, federation, receipt,
  or pending-delivery protocol state.
- Server-side plaintext generation, compaction, search, previewing,
  transcoding, or classification.
- A separate Chat recovery code or key escrow for administrators.
- Downloadable portable backup export/import in the initial release; it is the
  separately designed follow-up above.
- User-visible backup versions, point-in-time browsing, or selective
  conversation restore in V1.
- Locked/Vault chat backup in the standard Chat protection domain.
- Making backup events while no client can decrypt newly delivered messages.
- Guaranteeing freshness to a completely fresh device without an external
  witness.
- Silently evicting protected messages/media, publishing a partial message
  archive, or treating local encryption as server protection.

## Assumptions

- E2EE Chat History is always enabled after unified recovery provisioning and
  cannot be disabled independently of the account.
- The account master key and 24-word recovery mechanism remain the stable
  unified account recovery root.
- There is one latest logical restore point: one base plus its ordered tail.
- Eligible message events are small enough for the specified 64 KiB batching
  target; larger bounded records use dedicated canonical segment framing rather
  than violating API limits.
- Media is backed up independently and restored lazily.
- Homeserver backup storage is account-local; ordinary Chat federation remains
  responsible only for message and live-media delivery.
- The existing isolated display-history importer is the only permitted restore
  destination until a separately reviewed live-history merge model exists.
