# Chat backup security threat model

**Status:** normative for V1 continuous Chat history backup

This document extends [`chat-security-threat-model.md`](chat-security-threat-model.md)
and [`chat-media-security-threat-model.md`](chat-media-security-threat-model.md).
It covers server-hosted display-history backup, client compaction and import,
protected media, quota, retention, and account purge. It does not claim to back
up Direct/MLS transport state or provide a portable user export.

## Assets and trust boundaries

- The account master key, `ChatBackupRootV1`, derived encryption/signing keys,
  archive plaintext, media keys, conversations, messages, and private metadata
  are client-only.
- The authenticated account homeserver may order, quota, retain, stream, and
  delete opaque backup objects. It sees public format headers, lengths,
  digests, cursors, generations, operation IDs, device IDs, timing, object
  paths, and total/category byte accounting.
- SeaweedFS sees opaque paths, ciphertext length, and access timing. Database
  and object storage together are untrusted for confidentiality and integrity.
- An authorized linked installation may mutate the account's display archive,
  just as it may send or delete Chat content. Device revocation stops future
  writes but cannot make already exposed plaintext secret again.
- Backup remains at the account's own homeserver. A federated peer has no
  backup read/write role.

## Required fail-closed outcomes

| Threat | Control | Required outcome |
|---|---|---|
| Homeserver reads history | Random wrapped backup root; purpose-separated client encryption | Server receives only opaque archive/media ciphertext and bounded public accounting fields. |
| Wrong account, incarnation, purpose, suite, or domain | Typed envelope/header plus complete HKDF/AAD context | Reject before decrypt, reduction, or import. |
| Nonce reuse or object relocation | Random IDs/nonces and object-specific contexts | A ciphertext cannot authenticate at another segment, base, media ID, account, or incarnation. |
| Segment truncation, extension, reordering, or gap | Exact lengths/digests, final authentication, monotonic cursor, per-device sequence and predecessor chain | Restore stops before any history import. |
| Duplicate/replayed operation | Stable operation ID bound to request digest and unique account/device coordinates | Exact retry is idempotent; changed retry conflicts. |
| Malformed archive, duplicate record, or invalid mutation order | Bounded canonical parser and deterministic reducer | Reject the complete restore; do not partially expose records. |
| Deleted/expired content returns | Stable record identity, irreversible tombstones, absolute recipient expiry | Older messages, edits, reactions, media, and timer state cannot resurrect content. |
| Manifest forgery or rollback | Account-authorized backup signer, hash-linked generation, exact CAS, durable local generation/cursor/digest pin | Existing installations reject forgery, lower state, gaps, and same-position conflicts. |
| Fresh-device rollback by a malicious homeserver | Signature/hash-chain verification plus visible latest-protected status | Integrity is checked, but freshness cannot be guaranteed without an independent pin or witness; this is a stated V1 residual risk. |
| Crash during append acknowledgement | Durable local outbox and stable operation identity | Work remains pending or acknowledged; an ambiguous response resumes exactly after reload. |
| Crash during compaction | Staging plus reconciliation plus one manifest CAS transaction | Previous restore point or complete replacement remains valid; no hybrid generation is published. |
| Staged-object leak | Bounded staging lifetime and cleanup | Uncommitted bases are removed without changing the current restore point or charged steady-state usage. |
| Quota race or overcommit | Account row locking, exact charged bytes, transactional references | Concurrent append/media/compaction cannot exceed the dedicated Chat quota. |
| Full storage destroys recoverability | Durable pending queue plus tombstone/compaction headroom | Existing history is not evicted; deletion can commit and release space; pending work can resume. |
| Media-full blocks messages | Independent media work state and message append path | Media remains visibly pending while eligible message history continues. |
| Temporary retention deletes protected media | Separate delivery and history-media references/namespaces | Delivery cleanup never selects a protected history-media object. |
| Corrupt or substituted history media | Typed outer header, exact digest/length, final tag, source-length and zero-padding checks | Reject media before inner ciphertext/cache release; verified text remains usable. |
| Preview causes duplicate or unsafe storage | Preview remains bounded E2EE message content | No separate backup-media object or server-side preview decode is created. |
| Cross-account access or object leakage | JWT account scope, per-account keys/rows/prefixes, opaque account-local media IDs | Another account or federated peer cannot list, read, mutate, or reconcile the backup. |
| Account deletion leaves recoverable state | Transactional database purge, object-prefix deletion, exact Chat-byte reset | No backup rows, idempotency receipts, staging/reconciliation state, objects, or charged bytes remain. |
| Secret-bearing failure artifact | Safe reporter, closed durable checkpoints, aggregate database/log counts | Keys, phrases, tokens, ciphertext, capabilities, digests, and stable user identifiers are never retained. |
| Compression or declared-size bomb | V1 accepts no compression; public bounds checked before allocation | Unknown compressed wrappers and oversized declared plaintext are rejected before allocation/decompression. |

## Restore/import boundary

Parsing, cryptographic verification, cursor/device-chain validation, manifest
verification, and deterministic mutation reduction occur before the restored
history is exposed. An invalid base, tail, record, tombstone order, or media
reference aborts the restore as a unit. Media bytes themselves remain lazy and
may be unavailable without invalidating already verified message records.

Restore does not consume delivery state. It must not acknowledge a mailbox,
advance a mailbox cursor, emit a receipt, reuse a device ID, or install a
libsignal/MLS secret from the archive. Fresh protocol state is established only
through the normal signed device directory, Direct session, and MLS flows.

## Retention, quota, and availability

The dedicated Chat quota is server-authoritative because the server bears the
storage cost. The server can refuse new storage, withhold or delete ciphertext,
replay a self-consistent archive to an unpinned fresh device, or prevent
compaction. Those are availability/freshness failures, not confidentiality
breaks. The UI must preserve the last acknowledged timestamp and distinguish
offline, pending media, storage-full, invalid, and missing states.

Mailbox retention (30 days by default) and temporary delivery-media retention
(45 days by default) are operational policies. Zero disables either policy.
They do not define history retention: the latest committed backup persists for
the account lifetime and protected media is selected only by its committed
reference set.

## Residual risks

- A completely fresh browser has no independent local freshness pin. A
  malicious homeserver can replay an older internally valid signed restore
  point. An external witness or trusted freshness service is required to remove
  this limitation.
- A compromised account master key opens the wrapped backup root. This matches
  Kutup's unified recovery trust boundary.
- An authorized compromised client can create valid history mutations or omit
  new ones while it is the only usable online installation.
- Traffic analysis still reveals backup timing, ciphertext sizes, account-local
  access, compaction, and lazy-media fetches.
- Availability depends on the operator backing up PostgreSQL and SeaweedFS
  together. E2EE prevents the operator reading history; it does not recreate
  lost ciphertext.

## Verification obligations

Required tests cover wrong contexts and signatures, truncation/extension,
canonical archive rejection, cursor gaps, duplicate and reordered chains,
manifest rollback, zero-partial-import behavior, durable retry identity,
compaction failure checkpoints, exact quota boundaries, retention protection,
lazy-media corruption, cross-account isolation, and zero-state account purge.
The clean-browser and two-homeserver matrices must use empty browser contexts
and prove new Direct/MLS communication after restore. See
[`chat-backup.md`](chat-backup.md#required-gates) for the required CI layers.
