# Chat backup production test-hardening plan

**Status:** proposed

**Written:** 2026-08-11

**Depends on:** `docs/plans/continuous-e2ee-chat-backup.md`

**Scope:** continuous Chat backup, automatic fresh-browser restore, backup media,
quota and deletion, administrator-configured delivery retention, and federated
browser-loss recovery

## Outcome

Make the implemented continuous E2EE Chat backup safe to treat as Kutup's only
supported Chat-history restoration path. The work replaces the obsolete
device-transfer browser test and adds deterministic coverage at the crypto,
client coordinator, server API, object-storage, browser, and two-server levels.

The completed suite must prove all of the following:

- a committed Chat mutation is either durably pending locally or acknowledged
  by the account homeserver, never silently lost between those states;
- a clean browser restores the latest valid base plus complete ordered tail
  without another device, transport-state import, or plaintext server access;
- concurrent devices, retries, CAS conflicts, interrupted compaction, full
  quota, and object-storage failures preserve the last valid restore point;
- protected backup media and temporary delivery media have independent
  lifecycles and exact quota accounting;
- malformed, replayed, truncated, reordered, oversized, or context-substituted
  archives fail before display-history import; and
- the same guarantees hold for each account in a two-homeserver Direct/MLS
  conversation after both browser stores are lost.

## Testing principles

1. Test each invariant at the lowest layer that owns it. Do not put every edge
   case into Playwright.
2. Keep a small number of browser tests for user-visible recovery outcomes and
   real Web Crypto/WASM/IndexedDB integration.
3. Exercise server lifecycle and quota behavior through the HTTP API against
   real Postgres and SeaweedFS. Repository-only mocks are insufficient for
   transactions, object deletion, idempotency, and quota release.
4. Use deterministic clocks, schedulers, connectivity, UUIDs, and transport
   faults in coordinator tests. Do not rely on sleeps or mutate global browser
   state from individual tests.
5. Crash tests stop at named durable boundaries and construct a new
   coordinator over the same IndexedDB. Calling the same instance again is not
   a reload/resume test.
6. No production-only bypass endpoint may weaken authentication, signatures,
   quota, or object validation. Failure injection belongs in injected client
   adapters, test-only Rust modules, or the test reverse proxy.
7. All fixtures use generic Kutup-owned identities such as `user@kutup.dev`,
   `alice@a.test`, and `bob@b.test`. Logs and artifacts must not contain keys,
   recovery phrases, ciphertext, capabilities, tokens, or stable user IDs.

## Test layers and ownership

| Layer | Location | Owns |
|---|---|---|
| Crypto/protocol | `kutup-crypto`, `kutup-chat-proto`, WASM vector script, fuzz targets | typed contexts, bounds, canonical framing, signatures, wrong-purpose/account/suite rejection |
| Coordinator | new `frontend/src/chat/backup.test.ts` plus `backup-store.test.ts` | durable outbox, retries, restore reduction, pinning, compaction state machine, UI status |
| Server lifecycle | new `crates/kutup-server/tests/chat_backup_live.rs` | every endpoint, transactions, idempotency, CAS, quota, reconciliation, purge |
| One-server browser | replace spec 33 and add a focused media spec | automatic clean-browser restore, latest-protected UI, lazy media, history-loss UI |
| Two-server browser | extend the existing federation harness with a backup recovery spec | account-local backup of federated Direct/MLS display history and recovery after both stores are lost |

## Required testability work

These changes are structural seams, not alternate backup implementations.

### Browser coordinator dependencies

Replace direct use of the shared Axios client, `navigator.onLine`, `Date.now`,
`crypto.randomUUID`, and raw timers inside `ChatBackupCoordinator` with a small
injected runtime:

```ts
interface ChatBackupRuntime {
  transport: ChatBackupTransport
  connectivity: BackupConnectivity
  clock: BackupClock
  scheduler: BackupScheduler
  ids: BackupIdSource
}
```

Production adapters keep current behavior. Tests use deterministic in-memory
adapters. The transport interface exposes typed methods for status, provision,
append, segment pages, base stage/download, manifest CAS, media copy/upload/
download, and media reconciliation. This avoids global Axios mocking and lets
tests model an ambiguous response after a server commit.

Keep IndexedDB real in coordinator tests through `fake-indexeddb`. Add a narrow
`ChatBackupStore` interface only if transaction fault injection cannot be done
cleanly around the existing store functions. Production and test code must use
the same queue/ack transactions.

Expose cycle completion through a test-safe `flushNow()`/`settled()` operation
that uses the same serialized cycle as debounce, page-hidden, startup, and
online events. Do not make private methods public individually.

### Server integration harness

Create shared integration helpers under `crates/kutup-server/tests/common/` for:

- account registration/login and account-authority signing;
- Chat device and manifest setup;
- valid backup root envelope, signer authorization, segments, bases, manifests,
  and media metadata;
- authenticated JSON and multipart requests;
- exact database usage/category assertions; and
- paginated object-store listing with eventual-consistency polling bounded by a
  deadline.

Run `chat_backup_live.rs` against an isolated Compose project with Postgres and
SeaweedFS. Each test gets a unique account and object prefix. Tests may run in
parallel only after proving isolation; destructive account-purge cases remain
serial.

Refactor retention cleanup so the repository operation accepts an explicit
cutoff timestamp. The hourly job calculates the cutoff from the effective admin
setting and current clock. Integration tests call the same repository operation
with fixed timestamps instead of waiting 45 days.

### Failure checkpoints

Give coordinator compaction named test checkpoints:

1. current base and tail verified;
2. replacement base encrypted;
3. base upload acknowledged;
4. media reconciliation acknowledged;
5. manifest CAS acknowledged;
6. new local generation/cursor pin persisted.

The production adapter is a no-op. Tests may throw at a checkpoint, close the
database, and reopen. This is preferable to branching production logic on a
test flag.

## Implementation phases

### Phase 1 — Replace obsolete recovery acceptance coverage

Rewrite `tests/e2e/specs/33-chat-history-recovery.spec.ts`; remove
`cloneAuthenticatedInstall`, history request/approval/restore actions, and all
device-transfer test IDs.

The replacement scenario must:

1. register `user-<run>@kutup.dev`, complete unified recovery setup, and retain the
   recovery phrase only in test process memory;
2. sign in, open Note to Self, send a unique message, and wait for server-
   acknowledged **Protected** status plus a non-empty latest-protected time;
3. close the source context completely;
4. create a context with no cookies, session storage, local storage, Cache API,
   or IndexedDB and sign in normally;
5. verify history restores automatically, without another-device UI or a
   normal-path **Start from scratch** action;
6. reload and verify the restored message persists;
7. reply to the restored message and verify reply context survives another
   reload; and
8. verify no mailbox cursor, receipt, or device-transfer request was produced
   merely by restoration.

Add explicit data-test IDs for backup state and latest-protected time if the UI
does not already provide stable accessible selectors. Poll the status/API, not
an arbitrary timeout.

### Phase 2 — Complete server backup API lifecycle tests

Add live tests for every backup endpoint and its negative boundary.

#### Provision and status

- unprovisioned and provisioned status shapes;
- valid purpose-bound root envelope and account-authorized signer;
- exact idempotent replay returns the same result;
- reused operation ID with changed content conflicts;
- wrong account, incarnation, purpose, suite, authorization signature, and
  malformed envelope are rejected;
- another account cannot read, mutate, or delete the backup; and
- status byte categories equal database facts after each operation.

#### Segment append and listing

- first append and monotonic account cursor assignment;
- exact operation retry after an intentionally discarded response;
- per-device sequence and previous-digest enforcement;
- two devices append concurrently and both ciphertexts survive in cursor order;
- concurrent same-device appends allow only the valid chain head;
- stale account-manifest sequence, wrong ciphertext digest/length, oversized
  ciphertext, malformed base64, and foreign backup incarnation fail;
- pagination has no gaps, duplicates, or unstable continuation; and
- failed appends do not consume quota, advance heads, or leave receipts.

#### Base stage, media reconciliation, and manifest CAS

- stage and re-stage exact base idempotently;
- changed replay, truncation, digest mismatch, size limit, and wrong covered
  cursor fail without quota drift;
- commit requires an exact current generation, cursor, manifest digest, staged
  base binding, signer authorization, and completed media reconciliation;
- two compactors race against the same restore point: exactly one CAS succeeds;
- a failed CAS preserves the current committed base and complete tail;
- a successful CAS atomically publishes the new restore point, releases covered
  segments/old bases, and retains no partial manifest;
- abandoned staged bases are swept and their quota is released; and
- base download is authorized and byte-exact.

#### Complete deletion

- account deletion removes the backup envelope, status, manifests, bases,
  segments, device heads, receipts, reconciliation state, media references,
  media objects, staging rows, and all associated object-store keys;
- quota reaches exactly zero for every Chat category in the same lifecycle;
- deletion is safe to retry after partial object-store failure; and
- current local browser history is irrelevant to remote account purge.

### Phase 3 — Continuous outbox, retry, concurrency, and compaction tests

Add deterministic coordinator tests using real IndexedDB transactions and a
scripted transport.

#### Durable outbox

- one committed display mutation creates a sealed outbox entry and record
  update in one transaction;
- upload never starts before that transaction commits;
- reopening the database sends the same operation ID, sequence, digest, and
  ciphertext;
- an ambiguous response after server commit retries idempotently;
- acknowledgement deletes only the acknowledged entry and advances local pins
  atomically;
- failure between receipt and local acknowledgement resends safely after
  reload; and
- ordered pending entries stop at the first unresolved predecessor.

#### Scheduling and status

- short debounce coalesces mutations;
- 64 KiB threshold, page hidden, startup with pending work, and connectivity
  restoration trigger the same serialized flush path;
- offline never reports **Protected** for unacknowledged work;
- status transitions cover **Backing up**, **Offline**, **Media pending**,
  **Backup needs attention**, and **Protected** from server acknowledgements;
- latest-protected time changes only after acknowledgement; and
- simultaneous triggers do not run overlapping cycles.

#### Multiple devices

- two coordinator instances use independent device sequences and chains;
- interleaved server cursors restore deterministically;
- duplicate mutations reduce by stable record ID and mutation sequence; and
- edits, reaction replacement, deletes, and expiry tombstones never resurrect
  older state.

#### Compaction and crash recovery

- event-count, byte-count, and daily-opportunity thresholds trigger compaction;
- compaction fetches and verifies the complete current base and tail before
  staging a replacement;
- a CAS conflict refreshes the winner and retries from the new exact restore
  point rather than overwriting it;
- crash/reopen at each named checkpoint leaves either the old valid restore
  point or the committed new one;
- a crash after server CAS but before local pin learns and pins the committed
  generation on reopen;
- old base/tail are never treated as released before successful CAS; and
- staged orphan cleanup cannot remove a committed base.

### Phase 4 — Quota, deletion headroom, retention, and reconciliation

Use small per-test quotas so boundary behavior can be reached with kilobytes,
not multi-gigabyte fixtures.

#### Quota transitions

- exact charging for message segments, staged/committed bases, temporary
  delivery media, and protected history media;
- exact idempotent replay does not double-charge;
- message history can consume available quota up to the boundary;
- at full quota, ordinary new history remains durably pending and status warns
  the user;
- reserved deletion headroom accepts deletion tombstones and the compaction
  needed to release space while rejecting unrelated growth;
- media-full pauses new media protection but message-event backup continues;
- already protected media is never evicted to admit newer media;
- deleting messages/media reconciles references, objects, and usage exactly;
- interrupted release/reconciliation repairs undercount and overcount without
  publishing a partial restore point; and
- increasing an account quota allows pending work to resume without rewriting
  its operation identity.

#### Delivery retention

- default 30-day mailbox and 45-day temporary media settings are advertised;
- administrator overrides apply without restart; `0` disables expiry and the
  maximum accepted value is enforced;
- Direct and MLS mailbox ciphertext older than the effective cutoff is deleted,
  while newer and exact-boundary rows follow the documented comparison;
- an expired temporary media reference releases its delivery-media quota;
- a shared delivery object remains until its final delivery reference expires;
- the independently encrypted history-media object and its quota remain after
  temporary delivery expiry; and
- object deletion failure is recoverable by the orphan sweeper without a
  second quota release.

### Phase 5 — Backup media and lazy restore

Cover the complete media state machine at server, coordinator, and browser
layers.

#### Server and coordinator

- server-side copy wraps existing E2EE Chat-media ciphertext without receiving
  attachment plaintext/key and uses the exact padding bucket;
- copy is idempotent and rejects wrong source ownership, reference, media ID,
  outer key length, ciphertext metadata, and operation reuse;
- when the delivery object is gone, direct upload accepts a verified local
  encrypted copy and rejects truncation, digest/length mismatch, and oversized
  bodies;
- quota failure marks only that media item pending and does not discard the
  message descriptor or outbox;
- reconciliation is paginated, sorted, restart-safe, and rejects duplicate or
  missing pages;
- unreferenced backup media is removed only after a committed latest logical
  restore point no longer references it;
- media download begins only when the user opens the attachment;
- successful lazy restore verifies header, outer stream, source ciphertext,
  and attachment descriptor before cache/display;
- unavailable media leaves text history usable and presents a stable
  unavailable/pending action; and
- embedded encrypted previews do not create duplicate backup-media objects.

#### Browser acceptance

Add a focused Playwright media scenario that protects one small attachment,
waits for acknowledgement, expires/removes its temporary delivery copy through
the fixed-cutoff test control, clears the browser, restores text, and proves the
full media object is fetched only after **Open**. A second case removes the
backup-media object and verifies the unavailable presentation without breaking
the conversation.

### Phase 6 — Adversarial archive and rollback rejection

Extend Rust/WASM vectors, fuzz corpora, coordinator tests, and a small browser
response-interception suite.

Reject before plaintext import:

- wrong envelope purpose, account/backup incarnation, suite, protection domain,
  object purpose, device, sequence, previous digest, nonce, and authenticated
  length;
- truncated/extended ciphertext, malformed canonical JSON, unknown fields,
  duplicate record IDs, invalid mutation sequences, and excessive record count;
- cursor gaps, duplicate operations, repeated pages, reordered per-device tail,
  incomplete continuation, and tail replay before/after a base;
- manifest signature/binding failure and base digest/cursor mismatch;
- rollback below a locally pinned generation/cursor or conflicting digest at
  the same generation; and
- archive sizes and declared plaintext lengths above the fixed limits before a
  large allocation or history-store transaction occurs.

V1 does not compress backup archives. Therefore the “compression bomb” test is
a resource-exhaustion regression: any compressed wrapper/flag is unknown and
rejected, and oversized declared plaintext lengths fail before allocation. If a
future suite adds compression, bounded output bytes, expansion ratio, CPU time,
and nesting tests become a prerequisite for advertising that suite.

Browser interception tests may substitute base/tail responses only after the
normal authenticated request. They must verify that no partial restored record
is visible or stored and that the UI shows the specific retry/history-loss
state. The documented fresh-device old-but-valid server replay limitation is
not asserted away; only devices with an existing pin can detect that rollback
in V1.

### Phase 7 — Complete two-server federation/browser-loss matrix

Add `tests/e2e/specs/34-chat-backup-two-server-recovery.spec.ts` and run it from
the existing isolated federation Compose harness.

The scenario uses Alice on `a.test` and Bob on `b.test` and covers:

1. Direct messages in both directions, reply, edit, reaction replacement,
   delete, read state, disappearing timer, and eligible media;
2. a private MLS group with messages, reaction/edit/delete, disappearing
   content, and media;
3. server acknowledgement of each account's local backup cursor and all
   expected protected media;
4. sign-out/closure of every browser context and creation of clean contexts for
   both accounts;
5. recovery through each account's own password/master-key path, with automatic
   text restore and lazy media open;
6. proof that deleted/expired/view-once content does not return;
7. proof from database/object prefixes that Alice's backup exists only on
   `a.test` and Bob's only on `b.test`; and
8. creation of fresh Direct sessions and fresh active MLS state for new messages
   after display-history restore.

Stop and restart both homeservers after backup acknowledgement but before
fresh-browser recovery. This proves backup persistence is independent of
browser/device presence and in-memory server state.

## Coverage traceability

| Existing gap | Closing phase |
|---|---|
| Obsolete device-transfer browser spec | Phase 1 |
| Full backup API lifecycle | Phase 2 |
| Reload/resume, offline retry, concurrent append | Phase 3 |
| CAS conflict and compaction crash | Phase 3 |
| Quota-full, deletion headroom, release/reconciliation | Phase 4 |
| Media copy/upload/lazy/unavailable | Phase 5 |
| Default 45-day and admin retention expiry | Phase 4 |
| Account deletion and complete cleanup | Phase 2 |
| Two-server federation/browser loss | Phase 7 |
| Corrupt/replay/reordered/resource-exhaustion rejection | Phase 6 |

## CI integration

### Required pull-request gates

1. Existing Rust workspace, Chat core, WASM vectors, fuzz compilation, frontend
   Vitest, and production web build remain required.
2. Coordinator and backup-store tests run in the existing `web` job with fake
   IndexedDB and deterministic runtime adapters.
3. Add a `chat-backup-integration` job that starts isolated Postgres and
   SeaweedFS, builds the server once, runs `chat_backup_live.rs`, retention,
   quota, purge, and object reconciliation, then always tears the project down.
4. Replace spec 33 in the one-server browser gate. Sensitive backup jobs disable
   raw traces, screenshots, videos, page snapshots, and raw logs; on failure they
   upload only allow-listed durable checkpoints, log-category counts, and a
   redacted database-count summary.
5. Extend `chat-security-e2e` to run the two-server backup recovery spec after
   the existing federation API/security phases.

Keep Playwright `retries: 0`. Readiness uses bounded health polling, and state
convergence uses explicit backup cursor/status polling. No fixed multi-second
sleeps are accepted in new tests.

### Runtime and isolation targets

- protocol/coordinator tests: under 2 minutes combined on CI;
- server backup integration: under 10 minutes;
- one-server browser recovery/media: under 10 minutes;
- two-server federation/browser-loss matrix: under 25 minutes;
- the complete required pipeline remains below the existing 60-minute security
  job limit, splitting the backup integration job if necessary.

### Flake and release gate

Before declaring the rollout matrix complete:

- run coordinator crash/retry tests 100 times locally with randomized checkpoint
  selection;
- run server concurrency/CAS/quota tests 20 times against a clean Compose
  project;
- run single-server recovery 10 consecutive times;
- run the full two-server matrix 5 consecutive times; and
- require ten consecutive green default-branch CI runs with no retry mechanism
  hiding failures.

Any failure must retain enough sanitized evidence to identify the durable
boundary reached, account cursor/generation counts, quota categories, and object
counts without retaining secrets or opaque object contents.

## Delivery sequence

Implement as reviewable changes that leave the suite green at every boundary:

1. coordinator runtime/transport seams, shared server fixtures, and fixed-clock
   retention repository;
2. obsolete spec 33 replacement;
3. server lifecycle, idempotency, CAS, purge, and quota integration tests;
4. coordinator outbox/retry/concurrency/compaction tests;
5. media, retention, lazy restore, and unavailable-media tests;
6. adversarial/fuzz/browser rejection coverage;
7. two-server recovery matrix and final CI wiring; and
8. remove any remaining device-transfer-only fixture, selector, documentation,
   or CI reference after the replacement suite is green.

## Definition of done

This hardening work is complete only when:

- every row in the coverage traceability table has an automated required test;
- spec 33 performs true clean-browser server restore and contains no transfer
  request, approval, cloned session, or copied browser storage;
- all backup endpoints have success, idempotency, authorization, malformed
  input, quota, and interrupted-operation coverage as applicable;
- crash/reload tests prove the last valid restore point survives every durable
  boundary;
- default and administrator-overridden delivery retention are enforced without
  touching protected history media;
- account deletion leaves zero backup database rows, object-store keys, and
  charged Chat bytes;
- corrupt or rolled-back archives import zero plaintext records;
- both federated accounts restore Direct/MLS text and media in clean browsers
  and can establish new protocol state afterward;
- all new tests run in CI with no retries and meet the repeated-run flake gate;
  and
- `docs/plans/continuous-e2ee-chat-backup.md` can change its remaining rollout
  status from pending to complete with links to the required CI jobs.
