# Drive versions v2 — design

**Status:** agreed 2026-09-24, branch `feat/frontend-rewrite`.
Pre-tag: schema, API and storage change directly.

## Why

Every saved version is a full encrypted copy of the file — as in Proton
Drive, whose `createRevision` re-uploads the whole file as fresh blocks — but
the way Kutup keeps and counts them had defects:

1. **Quota bypass.** `POST /files/{id}/versions` charged the `sizeBytes` the
   client claimed, never the stored object's size.
2. **"Keep forever" was not forever.** All versions were S3 object versions
   of one key (`files/{id}/snapshot`); the bucket lifecycle expires
   noncurrent versions (30 days, beyond 50) and knows nothing of
   `keep_forever`.
3. **Deleted data was not deleted.** On the versioned bucket a delete only
   adds a delete marker, and the lifecycle keeps the newest 50 noncurrent
   versions — a purged file's bytes stayed indefinitely.
4. **No bound within 30 days.** Pruning required a version to be both older
   than 30 days *and* beyond the newest 50.
5. **Unchanged saves stored copies.** Save pressed twice = two full copies.
6. **The original upload lived forever** beside its versions: a document
   edited once kept two full copies for good.

## What the references do

- **Proton Drive** (`kutup-references/WebClients`): a revision is a full new
  upload; retention is a user setting (7, 30, 180, 365, 3650 days).
- **CryptPad** (`kutup-references/cryptpad`): a document's history is an
  append-only log of small encrypted patches; OnlyOffice documents add a
  full checkpoint every 100 patches (`CHECKPOINT_INTERVAL`); a named snapshot
  is a *pointer* (title + time on a log position, in the pad's metadata), so
  it costs nothing; the owner can "trim history" before the last checkpoint.
- **Google Docs / Time Machine:** older history is thinned (hourly, then
  daily) rather than cut off.

Kutup already has CryptPad's log for live collaboration (`file_update_log`,
truncated at each saved version). v2 takes CryptPad's pointer idea for named
versions, Proton's retention setting, and thinning. Log-based history for
office documents (versions as log positions over checkpoints) is the larger
follow-up; see "Later".

## Design

### One request stores a version

`POST /api/files/{id}/versions` (multipart) replaces the two-step
`snapshot-blob` + record:

- `file`: the sealed version (typed Drive file blob, header validated as
  today);
- `kind`: `file` (the whole file — office, whiteboard, restored copies) or
  `yjs` (a note's collaboration state);
- `seqAtSnapshot`, `docKeyId`, `label`, `keepForever` as before.

The server measures the body, checks quota with **that** size, stores it at
`files/{id}/versions/{versionId}` (a server-made id, one plain object per
version), inserts the row, truncates the update log and bumps the file's
modified time — one transaction, the object deleted again if it fails.
(Fixes 1; no orphans.)

### Every version its own object; deletes delete

Versions are no longer S3 object versions. Storage deletes remove every
object version of a key (`ListObjectVersions`), so deletes are real on a
versioned bucket too, and nothing depends on the bucket lifecycle; its rule
becomes a short safety net for anything overwritten (1 day, no retained
count). Rows from before v2 (with an `s3_version_id`) still download and are
deleted by version id. (Fixes 2, 3.)

### Named versions are pointers when nothing changed

"Save version" on unchanged content labels and keeps the latest version
instead of storing a copy (CryptPad's snapshot-as-pointer). Clients skip a
plain Save when the content is unchanged: notes know (no updates since the
last snapshot); office documents and whiteboards compare the bytes with the
last save. (Fixes 5.)

### Retention: thinning plus a user setting

Per file, never touching the newest version or `keep_forever` ones:

| Age | Kept |
|---|---|
| < 24 hours | every version |
| 1–7 days | the newest per hour |
| 7 days – retention | the newest per day |
| > retention | none |

Retention is the file **owner's** setting, `users.version_retention_days`:
7, 30 (default), 90, 180, 365 or 3650 days, in Account → Settings. The
policy is a pure function with unit tests; the job applies it and releases
quota. (Fixes 4.)

### The original is version zero

`GET /files/{id}/download` serves the file's latest `file`-kind version when
there is one (same sealed format, same binding), else the original — so the
CLI, public links and federated reads see edited content (closing the known
"public links serve the original" gap). Once a newer `file` version exists
and the original is older than retention, the job deletes the original blob
and releases its bytes (`files.original_pruned`); notes keep theirs (their
versions are Yjs state, not the file). (Fixes 6.)

## Accounting

A file costs its original (until pruned) plus each kept version, charged as
today (original to the uploader, versions to their author). Quota
reconciliation derives the same sums.

## Later

- **Log-based office history (CryptPad's model):** keep the OnlyOffice change
  log between checkpoints so versions become log positions; storage then
  grows with the edits, not the file size. Needs history replay in the
  OnlyOffice sandbox.
- **Chunk-level deduplication** across versions (content-defined chunks,
  per-file keys): its own crypto-format design, since it reveals which parts
  of a file changed.
