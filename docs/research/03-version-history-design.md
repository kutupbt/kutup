# Research: Version-history Design for the E2EE Collaborative Editor

**Captured:** 2026-05-04
**Scope:** How to give kutup users a Google-Drive-quality version history when the server stores ciphertext only and cannot read snapshot contents. Compares Drive, CryptPad, S3/SeaweedFS native versioning, and the snapshot+delta pattern from the E2EE-CRDT community, then recommends a concrete design.

---

## 1. Google Drive / Google Docs version history — concrete behavior

**Snapshot frequency.** Not officially documented. Drive collapses bursts of edits from a single author into time-bucketed, per-author "revisions" that appear minutes apart in the side panel. Internally Google uses an event-sourced log (every operation appended) with periodic materialised snapshots; restore = nearest snapshot + replay. ([Drive Help — Check activity & file versions](https://support.google.com/drive/answer/2409045), [Docs Help thread](https://support.google.com/docs/thread/158562878))

**Storage shape.** Operations log + periodic snapshots (deltas, not full copies, are the unit Drive bills you for; published quota cost of a Docs file is its current size only). For *uploaded* binaries (PDF/.xlsx/.docx) each version is a full object copy.

**Default retention.** Drive auto-purges old versions when **either 30 days have passed *or* there are 100 newer versions** — whichever comes first. ([Drive — Manage file revisions](https://developers.google.com/workspace/drive/api/guides/manage-revisions))

**Keep-forever / Named versions.** Right-click any revision → "Keep forever" exempts it from auto-purge. In Docs/Sheets/Slides, "Version history → Name version" labels milestones (a named version is implicitly kept forever).

**Session notion.** No formal "session." Open a Doc dormant for weeks and you continue the same operation log; the next edit becomes the next revision. Authors are identified per-op so the UI groups consecutive edits by the same user into one revision card.

**UI.** Right-rail timeline grouped per-author + time-bucketed, not per-keystroke. Click a revision to render the document at that op-log position.

---

## 2. CryptPad's history model

CryptPad runs a **history-keeper** node service. Documents are stored as **NDJSON files** at `cryptpad/datastore/<first-2-chars>/<channel-id>.ndjson`, one ciphertext patch per line. ([CryptPad — Database](https://docs.cryptpad.org/en/dev_guide/database.html))

**Checkpoint cadence.** Every ~50 patches the *client* emits a special "checkpoint" patch — a single op that deletes the document and re-inserts the current state. Checkpoints carry a marker added *after* encryption so the server can recognise them without reading the ciphertext.

**Compaction.** When a client opens a doc the server streams patches **starting from the penultimate checkpoint** (penultimate, not last, to recover from partial writes). Owners can compact: drop everything older than the last two checkpoints. There is no "named version" feature — history is a flat patch log.

**Re-joining client.** Receives the checkpoint + tail of patches and replays into the local CRDT.

---

## 3. SeaweedFS / S3 versioning

**SeaweedFS support.** Versioning is supported in modern SeaweedFS (confirmed by the maintainer in late 2025). Versions are kept in a hidden `.versions` subdirectory; version IDs are timestamp-derived. Enable with the standard AWS call: `aws s3api put-bucket-versioning --bucket X --versioning-configuration Status=Enabled`. ([Discussion #2627](https://github.com/seaweedfs/seaweedfs/discussions/2627), [SeaweedFS S3 Bucket Operations](https://deepwiki.com/seaweedfs/seaweedfs/3.3.2-s3-bucket-operations))

**Lifecycle.** SeaweedFS translates S3 lifecycle rules into native TTLs. `aws_s3_bucket_lifecycle_configuration` is accepted and persisted. NoncurrentVersionExpiration with `NewerNoncurrentVersions` (keep last N) and `NoncurrentDays` work. ([Issue #8754](https://github.com/seaweedfs/seaweedfs/issues/8754), [Discussion #2745](https://github.com/seaweedfs/seaweedfs/discussions/2745))

**E2EE compatibility.** Lifecycle rules evaluate object metadata only — key, timestamp, version count, tags. Server never reads ciphertext, so lifecycle is fully usable in zero-knowledge deployments.

**Cost shape.** AWS S3 explicitly states: *"Each version of an object is the entire object; it is not just a diff from the previous version. Thus, if you have three versions of an object stored, you are charged for three objects"* — **no native dedup**. SeaweedFS behaves the same. Implication: full snapshots of large `.xlsx` files multiply storage linearly. Cap with lifecycle (`NewerNoncurrentVersions=N`, `NoncurrentDays=30`).

---

## 4. Snapshot+delta patterns in E2EE collab editors

**Serenity Notes / Secsync (Nik Graf).** Architecture splits into **Snapshots** (encrypted full Yjs state) and **Updates** (encrypted small CRDT updates referencing a snapshot). Updates persisted with monotonic integer version numbers; snapshots rotated on member change or symmetric-key rotation, at which point the relay drops the old snapshot and its updates. Default trigger is event-based (membership change, key rotation) rather than purely time-based. ([Secsync GitHub](https://github.com/serenity-kit/secsync), [Tag1 Part 2](https://www.tag1consulting.com/blog/deep-dive-end-end-encryption-e2ee-yjs-part-2))

**Yjs GC pitfall.** Canonical advice: **do not disable GC just to keep snapshots inside the live Y.Doc.** Disabled-GC docs blow up CPU, disk, and bandwidth. Recommended pattern: keep GC *on* in the live `Y.Doc`, store snapshot-tagged Y.Doc binaries (`Y.encodeStateAsUpdateV2`) **as separate documents** outside the live one, retrievable on demand and diff-rendered against live. ([discuss.yjs.dev — GC and Snapshotting](https://discuss.yjs.dev/t/garbage-collection-and-version-snapshotting/1839), [Palanikannan — Yjs Version History in Production](https://www.palanikannan.com/blogs/yjs-snapshots-part-5-production))

**Notesnook / Standard Notes.** Notesnook keeps version history per editor session locally + sync; each save event = a version, retained per device. Standard Notes gates revision history by plan (free = current session only). Both use XChaCha20-Poly1305 per-item encryption. ([Notesnook Help](https://help.notesnook.com/note-version-history), [Standard Notes Plans](https://standardnotes.com/plans))

**Boundary trigger — should it be time, size, or event?** Prior art says **all three, layered**:
- Size-based (every N updates) — guarantees progress under heavy editing (CryptPad, Secsync).
- Idle/debounce — produces user-meaningful "save points" (Drive, Notesnook).
- Explicit "Name this version" — milestones (Drive, Docs).

---

## Final synthesis — recommended versioning model

**Two-tier log: deltas in Postgres, snapshots in SeaweedFS-S3.**

**Live update log (delta layer).** Persist each encrypted Yjs/OnlyOffice update as a Postgres row: `(file_id, seq bigserial, ciphertext bytea, author_id, ts)`. Postgres — not S3 — because updates are small (often < 1 KB), high-frequency, and need cheap transactional appends and range queries. Stream them to clients over WebSocket; on reconnect, clients send their last-seen `seq` and pull the tail.

**Snapshot layer in S3.** Periodically materialise an encrypted Yjs state vector (or OnlyOffice OOXML for office docs) and PUT it to `s3://bucket/files/<file_id>/snapshot` with **bucket versioning ON**. Each PUT becomes a new noncurrent version automatically; metadata DB stores `(file_id, version_id, seq_at_snapshot, author_id, ts, name nullable, keep_forever bool)`. Once snapshot N is durable, delete delta rows with `seq <= seq_at_snapshot`. Clients hydrate from latest snapshot + tail of deltas — exactly CryptPad's penultimate-checkpoint pattern.

**When a snapshot is created** — layered triggers:

1. **Idle debounce: 30 s after the last edit** when ≥ 1 update accumulated. Produces Drive-style "version cards."
2. **Hard ceiling: every 200 updates** in the delta log, even under continuous editing.
3. **Explicit "Save version" / "Name version"** button — always snapshots, sets `name` + `keep_forever=true`.
4. **Membership change** (collection share added/removed → key rotation).

**Retention** (mirrors Drive's "30 days OR 100 versions, whichever first; named forever"):

- Keep **last 30 days** OR **last 50 snapshots**, whichever yields more.
- Named/keep-forever versions exempt from purge — kept indefinitely.
- Implementation: cleanup job on the backend (server can read snapshot *metadata*: file_id, timestamp, label, keep_forever — even though it can't read content). Deletes both the S3 noncurrent version and the `file_versions` row in one transaction.

**UI** (right-side panel like Drive):
- Timeline grouped per-author, time-bucketed.
- Each row: timestamp · author avatar(s) · optional name · ⋯ menu → **Restore** / **Name** / **Keep forever** / **Make a copy**.
- Click a row → render the snapshot in a read-only editor pane next to current state (diff happens client-side after decrypting both).
- Live deltas between snapshots are *not* exposed individually — internal consistency only.

**Restore** = client downloads + decrypts old snapshot → posts a fresh snapshot under the current key epoch with that content → log truncated. Non-destructive: the old version stays in history.

**Same as Drive / different from Drive.** Same: log+snapshot model, time+author bucketing, "Keep forever / Name version," 30-day default purge. Different: server stores only ciphertext so diffing and previews happen client-side after decrypting both states, and named/keep-forever versions cost real storage (no server-side dedup).

---

## Sources

- [Google Drive Help — Check activity & file versions](https://support.google.com/drive/answer/2409045)
- [Google for Developers — Manage file revisions](https://developers.google.com/workspace/drive/api/guides/manage-revisions)
- [CryptPad Docs — Database](https://docs.cryptpad.org/en/dev_guide/database.html)
- [CryptPad Docs — ChainPad and Listmap](https://docs.cryptpad.org/en/dev_guide/client/chainpad.html)
- [AWS — S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html)
- [AWS Storage Blog — Reducing costs with fewer noncurrent versions](https://aws.amazon.com/blogs/storage/reduce-storage-costs-with-fewer-noncurrent-versions-using-amazon-s3-lifecycle/)
- [SeaweedFS Discussion #2627 — Object versioning support](https://github.com/seaweedfs/seaweedfs/discussions/2627)
- [SeaweedFS Discussion #2745 — Lifecycle Expiration](https://github.com/seaweedfs/seaweedfs/discussions/2745)
- [Secsync (serenity-kit) — Architecture for E2EE CRDTs](https://github.com/serenity-kit/secsync)
- [Tag1 — Deep Dive into E2EE in Yjs, Part 2](https://www.tag1consulting.com/blog/deep-dive-end-end-encryption-e2ee-yjs-part-2)
- [discuss.yjs.dev — Garbage Collection and Version Snapshotting](https://discuss.yjs.dev/t/garbage-collection-and-version-snapshotting/1839)
- [Palanikannan — Yjs Version History in Production](https://www.palanikannan.com/blogs/yjs-snapshots-part-5-production)
- [Notesnook Help — Note version history](https://help.notesnook.com/note-version-history)
