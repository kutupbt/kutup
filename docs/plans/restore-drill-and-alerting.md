# Restore drill and alerting minimum

Status: **approved** 2026-11-12 (drafted by the consultant session, 2026-11-10). Two small pieces of
operations work to finish before the wipe release, so that "no third wipe"
does not depend on the production machine surviving.

Read for this note, on `origin/wipe-2`: `scripts/backup-postgres.sh`,
`scripts/backup-stalwart.sh`, the headings of `docs/self-hosting.md`
("Storage and Backups", "Database backups", "Mail backups"),
`crates/kutup-server/src/telemetry.rs`, the `/api/health` handler in
`main.rs`, and `.env.example`. I did not look at the production machine.

## Part 1. The restore drill

### What exists

- Encrypted PostgreSQL dumps to the object store on a timer, with pruning
  (`scripts/backup-postgres.sh`), and the same for Stalwart's data volume
  (`scripts/backup-stalwart.sh`, which also has `--restore`).
- Still open, from the roadmap ("Backup / restore CLI"): a second copy of the
  blobs, a consistent pair of database and blobs, and a restore that has been
  run.

### Gaps to close first

1. **The dumps live in the same bucket as the data.** One lost bucket or one
   leaked storage key loses both. Send backups to a second bucket with its
   own credentials (write-only from the server if the provider allows).
2. **Blobs have one copy.** Turn on object versioning or a lifecycle-protected
   replica bucket at the provider. The blobs are ciphertext, so a replica
   leaks nothing new.
3. **The dump cipher has no integrity check.** The script uses
   `openssl enc -aes-256-cbc -pbkdf2` (line 63). CBC without a MAC means a
   changed backup decrypts to something, and the restore finds out late or
   never. Use `age` with a passphrase or a recipient key, or add an HMAC over
   the file and check it before decrypting.
4. **Secrets outside the database.** A restore needs everything in `.env`
   (`JWT_SECRET`, `OPAQUE_SETUP_KEYS`, `KUTUP_BACKUP_PASSPHRASE`, the storage
   keys) and any key files on disk. Without `OPAQUE_SETUP_KEYS` no one can
   sign in to a restored database. With L1, the server key list joins this
   set: without it every sealed server field and the destruction replay are
   lost. Write the list of secrets down once and keep an offline copy.
5. **Consistency.** A dump taken at time T refers to blobs that must exist.
   Uploads after T are harmless (orphans). Deletions after T are the risk: a
   restored row can name a purged blob. Rule: the purge jobs (`jobs.rs`,
   trash and version retention, orphan sweep) keep deleted blobs for at
   least the backup interval plus a margin, or the bucket's versioning keeps
   them. Make that margin a setting and state it in the runbook.

### The drill

Run it on the dev VM in a lane stack, from nothing but what a lost machine
would leave: the backup bucket, the blob bucket (or its replica) and the
offline secrets.

1. Start an empty stack from the release images. Do not copy anything from
   the running production stack.
2. Fetch and decrypt the newest database dump; `pg_restore` into the empty
   database. Record the time taken.
3. Point the stack at a **copy** of the blob bucket (never the live one: a
   sweep job in the restored stack must not delete production blobs). Start
   with every background job off, then turn them on.
4. Restore Stalwart's volume with `--restore`.
5. Check, as a user:
   - sign in with password and with the recovery phrase;
   - open a file uploaded before the dump, a large one included;
   - open one uploaded after the dump: expect a clean "missing" state, not a
     crash;
   - Chat history restores from the Chat backup on a new browser;
   - Mail: old messages open; a new message sends and arrives (DKIM key
     restored);
   - a Pass vault opens;
   - a second server still federates with the restored one (its federation
     identity came back).
6. Check, as the operator: the migrations table matches the release;
   `kutup-server check-config` passes; with L4, the destruction replay runs
   and accounts destroyed after the dump stay destroyed.
7. Write down: time to restore, the data lost (the backup interval), every
   step that needed knowledge not in the runbook. Fix the runbook, not the
   memory.

Repeat after the wipe release and after any change to backups. A scripted
version of steps 1 to 4 (a `restore-drill.sh` script (to be written)) is worth having; steps
5 and 6 can reuse existing browser specs against the restored stack.

### Done means

A dated entry in `docs/self-hosting.md` ("Restore, as last run") with the two
numbers, and the three gaps above closed or explicitly accepted.

## Part 2. The alerting minimum

### What exists

- `/api/health` answers without touching the database or storage.
- OpenTelemetry export is opt-in and scoped to Chat security paths
  (`telemetry.rs`).
- Nothing tells a person that something is wrong.

### Principle

A family beta needs few alerts, each one meaning "a person must act". No
dashboards yet. Alerts go to the operator by a channel that does not depend
on the machine being watched.

### Two pieces

**A. A readiness endpoint** (`/api/health/ready`, admin token or localhost
only): the database answers, a small object can be written and read back,
the mail server accepts a connection, the background jobs have each run
within their expected interval (each job records its last success), and the
newest backup's age. It returns one JSON with a status per check. The admin
"System status" page on the roadmap can read the same endpoint later.

**B. A watcher outside the server process**, a timer script on the host or,
better, on a second machine, that sends a message when a check fails twice
in a row and again when it recovers:

| Check | Fails when | Why it matters |
|---|---|---|
| Site reachable from outside | the public URL fails over HTTPS | the only check that sees DNS, TLS and the proxy |
| Readiness | any part is not ok | database, storage or jobs are down |
| Certificate | under 14 days left | renewal is silently broken |
| Disk | under 15 % free on any volume | PostgreSQL stops on a full disk |
| Backup age | newest database or mail backup older than two intervals | the backup timer died |
| Mail queue | messages waiting longer than an hour, or outbound rejected | mail fails silently otherwise |
| Mail reputation | DKIM, SPF or DMARC records no longer match | a DNS change broke delivery |
| Containers | a restart loop, or an image differing from the release | a bad deploy |
| Federation outbox | oldest item older than an hour | a peer or our signing is broken |
| Sign-in failures | a sharp rise | an attack, or OPAQUE setup keys are wrong |

Channel: the simplest that reaches a phone and is independent of Kutup's own
mail and Chat, for example a push service or an SMS gateway, with email to an
outside address as a second path. Which one is the user's choice.

### Not now

Metrics storage, dashboards, tracing beyond Chat, per-user error tracking.
They are worth having with paying users; they are not needed to know the
service is down.

### Done means

The readiness endpoint exists; the watcher runs somewhere other than inside
the server; each alert has been fired once on purpose and reached the phone;
the runbook says what to do for each row.

## Order

1. Second backup bucket, blob versioning, the authenticated cipher (small).
2. The readiness endpoint with job heartbeats (small; core, not enterprise).
3. The watcher and the channel.
4. The drill, once, before the wipe release; fix what it finds.
