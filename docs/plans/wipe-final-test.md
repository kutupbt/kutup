# The final pre-wipe test: runbook

Status: approved 2026-11-18 by the main session (Q-1: E1 required; Q-2: suite files and a master-only CI job; F-2 to F-4 done on this branch; F-5 comes with #413).

This is the one full test the wipe waits for (the user's rule since
2026-11-09: build every pre-wipe feature, then test once, then wipe). It lists, in order,
what runs on the final tree, with the commands, the lane, the expected
result and a rough duration, so it can be run without guesswork. Every step
says what "pass" means. A failure is recorded in §9 and fixed on the tree,
and the steps it touches run again; nothing is waved through.

Durations are rough, from earlier runs on agentic01 (50 cores, Docker on
tmpfs). Lane N means `source ../move-to-vm/lanes/laneN.sh` first, from the
worktree root (one lane per session: 1 main, 2 second, 3 third).

## 0. Before the test: the user's prerequisites

These can't be done by a session. The test can start without them, but
§6 (restore drill) and §8 (deploy) can't run until they are done. **The
wipe date waits on U1–U3**: the staging drill E1 (§6.1) is required before
the wipe, and it needs the backup bucket, the age key and the scratch
bucket.

| # | What | Why | Who |
|---|---|---|---|
| U1 | **A backup bucket**, apart from the data bucket (ideally another provider or account), with an access key that can reach **only** it: write, list, delete. Values for `BACKUP_S3_ENDPOINT`, `BACKUP_S3_BUCKET`, `BACKUP_S3_ACCESS_KEY`, `BACKUP_S3_SECRET_KEY`, `BACKUP_S3_REGION` (`auto` for R2). | The backup scripts refuse the data bucket or its key (self-hosting.md, "Backups"). The old nightly backups went to the data bucket under `database-backups/`. | user (provider console) |
| U2 | **The age key pair**, made offline: `age-keygen -o kutup-backup.key`. The public `age1…` key goes in `.env` as `KUTUP_BACKUP_AGE_RECIPIENT`; the identity file never goes on the server. At least two offline copies. | Backups are age-encrypted to it; the drill needs the identity. | user |
| U3 | **A scratch bucket for the drill**, its name containing `drill`, at the same provider as the data bucket, with a key that can write it and read the data bucket. | `restore-drill.sh --scratch-bucket`: the restored stack must never see production blobs. | user |
| U4 | **Blob versioning or a replica** on the data bucket (R2: object versioning or a replication rule). | The data bucket holds the only copy of every file's ciphertext. | user |
| U5 | **Offline copy of the whole new `.env`** (§8.2), kept with the age identity, `OPAQUE_SETUP_KEYS` included. | `OPAQUE_SETUP_KEYS` also wraps every account data key (L1): without it, every sealed server field is lost. | user, after §8.2 |
| U6 | **Decisions:** `KUTUP_CSP_ENFORCE` at the wipe (0 = report-only, 1 = enforced; §5.4 informs it); `CHAT_GROUPS` on or off at the wipe; registration mode after the wipe. | They change what §4 and §8 run. | user |

## 1. Freeze the final tree

1. The main session names the final tree: `wipe/final-<date>`, the wipe
   stack (W7 groups 1–4 and the rest, the API pass, the merged feature
   branches) merged in its landing order. Record its SHA here. From now on
   a fix is a commit on it, and §9 says which steps re-run.
2. A fresh worktree for the test: `git worktree add ../wt-final wipe/final-<date>`.
   - Link its target into RAM: `mkdir -p ~/ram/targets/wt-final && ln -s ~/ram/targets/wt-final target`.
   - Copy `nginx/certs/` from the main checkout (§4.1 makes a fresh self-signed one if missing).
   - Run `npm ci --prefix tests/e2e` and `npx --prefix tests/e2e playwright install chromium webkit`.
3. **Machine checks** (lane 1, 5 min):
   - `df -h / ~/ram`: `/` has more than 60 GB free; `~/ram` has more than 20 GB. No other session's target may sit above 15 GB in `~/ram`.
   - Docker runs from tmpfs and is empty after a reboot: run `docker builder prune -f --filter until=20m`.
   - The tools exist: `cargo-deny`, `age`, `jq`, `aws` (aws-cli v2), `ffmpeg` with `libx264` (spec 192 on WebKit is skipped without it), and Node 22.18 or newer.
   - `move-to-vm/fix-localhost-dns.sh` has run: `getent hosts drive.localhost` answers 127.0.0.1.
4. **Tell the other sessions** that the full test owns lanes 1–3 and Docker until §7 ends. Any `docker compose up/down` elsewhere breaks running browser specs with `ERR_NETWORK_CHANGED`.

## 2. Phase A: the code gates (no stacks)

One after another in lane 1, on the final tree. They share the target and
all the cores, so nothing else builds meanwhile (rustc has segfaulted under
memory pressure from parallel image builds).

| Step | Command | Pass | Time |
|---|---|---|---|
| A1 | `scripts/gate.sh static` (formatting, clippy on every root, docs, labels, crypto exceptions, migrations against `KUTUP_MIGRATION_BASE=<base of the wipe stack>`, restore drill dry runs, `cargo deny`) | exits 0 | 15 min |
| A2 | `scripts/gate.sh rust` (workspace tests, Chat core tests, FFI and fuzz compile; the vendored keepass tests once `feat/pass-vendor-tests` is in the tree) | exits 0 | 25 min |
| A3 | `cargo test --locked --manifest-path crates/kutup-client-ffi/Cargo.toml --all-targets` (the gate only compiles the FFI) | all pass | 8 min |
| A4 | the vendored keepass test script from the Pass stack (`feat/pass-vendor-tests`), when not already in A2's output (63 pass, 2 ignored on the Pass stack) | 63 passed, 2 ignored | 1 min |
| A5 | `scripts/gate.sh web` (WASM builds and vectors, the size budgets, tsc, lint, vitest, production build, `check-app-bundles.mjs`) | exits 0; every WASM module under its budget (the size table is pasted in §9) | 25 min |

Phase A takes about 75 min. **If A fails, stop**: everything later builds the same tree.

## 3. Phase B: the live gates (their own stacks)

Each gate builds and tears down its own Compose project, named per lane, so
the three run at once, one per lane. They do churn Docker networks, so no
browser suite runs during Phase B.

| Lane | Step | Command | Pass | Time |
|---|---|---|---|---|
| 1 | B1 | `scripts/gate.sh live backup`: Postgres and SeaweedFS lifecycle, Chat backup, account closing, the app role (`tests/chat-backup/compose.yml` sets `POSTGRES_APP_USER`) | exits 0 | 35 min |
| 2 | B2 | `scripts/gate.sh live federation`: the two-server gate, Drive and Chat over the v2 stack, specs 25, 32, 34 and 161 in Chromium | exits 0 | 50 min |
| 3 | B3 | `scripts/gate.sh live mail`: Stalwart, SMTP in and out, DKIM, GnuPG WKD, deletion leaves nothing | exits 0 | 25 min |
| 3 | B4 | then `scripts/gate.sh live mail-domains`: custom domains with CoreDNS, then the `mail-domains` browser suite | exits 0 | 20 min |

Phase B takes about 50 min of wall time.
- **Known VM failure:** B3 may fail only on "the custom domain's message never reached the sink" with its 35 tests green; it has done so on earlier trees where CI's mail gate passed. Record it, compare with the base tree, and let master CI's mail gate (§7) give the verdict.
- **Images:** build the gates' images one lane at a time if `~/ram` is above 80%. `KUTUP_FEDERATION_IMAGE` is per lane, so lanes don't replace each other's.

## 4. Phase C: the browser suites

### 4.1 The stacks

Two single-server stacks, both up **before** any suite starts, and neither
taken down until §4.3 ends.

- **Stack P** (lane 1, production-like): `docker-compose.yml` plus `tests/e2e/docker-compose.isolated.yml`.
  - That means production mode, the app role (`POSTGRES_APP_USER=kutup_app`), and `MAIL_OUTSIDE_SENDING=on`.
  - Plus `KUTUP_CSP_ENFORCE=0` and `CHAT_GROUPS=true`.
  - Set `E2E_PSQL` (absolute `-f` paths) so specs 157, 162 and 163 run.
  - Set `E2E_OPAQUE_ROTATE` (the `move-to-vm/local-stack-feat/rotate-opaque.sh` pattern with this stack's project) so spec 156's rotation runs.
  - `E2E_TRUST_LOCAL_CERT=1`.
- **Stack T** (lane 2, CI-like): `docker-compose.yml` with CI's mail-browser env (APP_ENV=test, `RATE_LIMITS_RELAXED`, `MAIL_DEFAULT_DELAY_SEND_SECONDS=0`, `CHAT_GROUPS=true`, the same `E2E_PSQL`). It is used for the specs that were written against CI's stack.

Bring them up one after another: `docker compose up --detach --build --wait`,
then `curl --fail --insecure https://localhost:<port>/api/v1/auth/settings` (the API pass's versioned path; the bare `/api/…` answers 426)
(10 min each; the frontend image bakes the WASM).

**Pass:** both answer. On Stack P, `docker compose logs backend` has no
"logs are not append-only" warning: the app role is in force (L2).

### 4.2 Suites and specs

One Playwright process per lane at a time. All with
`E2E_CSP_STRICT=1`: a test that saw any CSP violation, report-only included,
fails after its body. So a failure says whether it was the behaviour or the
policy (§5.4 sorts them).

| Lane / stack | Step | Command | Pass | Time |
|---|---|---|---|---|
| 1 / P | C1 | `scripts/gate.sh browser mail` (42 specs) | all pass | 45 min |
| 1 / P | C2 | `scripts/gate.sh browser contacts calendar office` (8) | all pass | 15 min |
| 1 / P | C3 | `scripts/gate.sh browser account pass` (23; 156 with its rotation, 157 with E2E_PSQL) | all pass, 156 and 157 not skipped | 30 min |
| 1 / P | C4 | `scripts/gate.sh browser webkit` (190–192 on WebKit) | 191 and 192 pass (190 skips by design); each spec's `playback path` annotation recorded in §9 | 10 min |
| 1 / P | C5 | `KUTUP_LIVE_SERVER=http://<P backend IP>:3000 KUTUP_LIVE_DATABASE_URL=… scripts/gate.sh live pass` | exits 0 | 10 min |
| 2 / T | C6 | `scripts/gate.sh browser chat-backup` (10) | all pass | 30 min |
| 2 / T | C7 | Restart T's backend with `CHAT_GROUPS` unset (spec 39 checks groups off), then `KUTUP_CLI=$PWD/target/debug/kutup scripts/gate.sh browser drive office-docs chat account-misc` (38 specs, §10 F-1; build the CLI first with `cargo build -p kutup-cli`, or spec 114 skips) | all pass, 114 not skipped; 41 and 42 run only with T up under `--profile sfu`, else they skip with a message (record which) | 60 min |
| 3 | C9 | The CLI against Stack P, from lane 3 (no stack of its own): `KUTUP_SERVER=https://drive.localhost:<P port> KUTUP_INSECURE_TLS=1` with `scripts/verify-cli.sh`, `scripts/verify-mk-rotation.sh`, `scripts/verify-yjs-sync.sh` and `E2E_PSQL=… scripts/verify-cli-account-head.sh` | each exits 0 | 20 min |

Phase C takes about 100 min (lane 1 is the long one); lanes 2 and 3 finish inside it.

### 4.3 The instance id (API pass §5) on Stack P

After C1–C5, so nothing else is using Stack P (15 min):

1. In Chromium (Playwright codegen or by hand), sign up, upload a file, open
   Chat and Pass, so IndexedDB and localStorage hold state on the drive,
   chat and pass origins. With the CLI: `kutup login` on a profile, then `kutup ls`.
2. Change the instance:
   `$E2E_PSQL <<< "UPDATE server_instance SET id = decode(md5(random()::text), 'hex')"`,
   then `docker compose restart backend`.
3. Reload each app tab. **Pass:**
   - the sign-in page shows "This server was reset; local data was removed";
   - `indexedDB.databases()` lists only the anchor `kutup.account.revisionsSeen`;
   - no `kutup*` localStorage keys remain but the manifest pins (`kutup.account.manifestPins:<account>`) and the look (`kutup.ui.theme`, `kutup.ui.language`).
4. A tab left open and idle: its next request reloads it (the header changed), with the same result.
5. CLI: `kutup ls` exits 3 with "… was reset …". The profile keeps `manifest_pin`; the session and sync state are gone.
6. `kutup-server reset-instance-id` on Stack P is refused ("account(s) exist").

The API pass's own browser spec for this, if it has landed, runs in C3's
list instead; then only 4–6 stay manual.

## 5. Phase D: reading the results

### 5.1 Logs of every stack (before it is taken down)

`docker compose logs --no-color backend > <dir>/<stack>-backend.log` for P,
T and each live gate's stack that a run keeps.

**Pass:** no `panicked`, no `ERROR` lines other than the ones a spec causes
on purpose. Those are listed in §9 as each is understood; none is left
unexplained.

### 5.2 Chromium network churn

Any browser failure: grep its trace for `ERR_NETWORK_CHANGED` before suspecting code. If it's there, re-run that spec alone and record both runs.

### 5.3 Size and timing

Paste A5's WASM table and the app bundle check's output in §9.

### 5.4 CSP

Two sources:
- the `csp-violations` attachments of the strict run (§4.2);
- the server's log, since reports are logged, never stored:
  `grep 'content security policy violation' <stack>-backend.log | sed 's/.*violation//' | sort | uniq -c | sort -rn`.

Sort every distinct (app host, directive, blocked origin or kind) into:
- (a) a known gap from docs/content-security-policy.md, "Known gaps before enforcing";
- (b) a bug to fix before the wipe.

**Pass for U6:**
- `KUTUP_CSP_ENFORCE=1` at the wipe only if (b) is empty and every (a) is closed.
- Then re-run C1–C3 on Stack P restarted with `KUTUP_CSP_ENFORCE=1` (the frontend container only), which adds about 90 min.
- Otherwise the wipe ships report-only (0), and §8.6 reads production's reports in the first week.

## 6. Phase E: the restore drill and the outbound check

### 6.1 Which backup the drill restores

The squashed baseline refuses a database built by the old migration chain,
so a dump of today's kutup.dev can't be restored on the final release.
Two drills:

- **E1, before the wipe (staging), lane 3, 60 min, needs U1–U3:**
  1. A staging stack from the final images (`scripts/publish-images.sh` on
     the final tree, without pushing; or `docker compose build`).
  2. Point its backups at the U1 bucket under a `staging/` prefix (or a
     second test bucket), and its data at a scratch bucket of its own.
  3. Make data with the CLI (§4.2 C9's scripts) and in a browser.
  4. Run `scripts/backup-postgres.sh` and `scripts/backup-stalwart.sh`.
  5. Then `scripts/restore-drill.sh --env <staging .env> --identity kutup-backup.key --images <tag> --source-bucket <staging data> --scratch-bucket <name>-drill --lane 3`.
  6. Then the checks of self-hosting.md "Restore drill" steps 5–6:
     - sign in with the password and with the phrase;
     - a file from before the dump opens; one from after shows "missing";
     - Chat history comes back in a new browser; a Pass vault opens;
     - `max(version)` in `_sqlx_migrations` matches the release, `check-config` passes, readiness answers.
  7. Then `scripts/restore-drill.sh --down`, and empty the scratch bucket.
- **E2, after the wipe (production), within a day:** the same drill against
  the first nightly backup of the new kutup.dev, with production's `.env`
  copy (U5). Record the first row of "Restore, as last run" in
  self-hosting.md.

**Pass:** every check holds; the timings and the data-loss window are written
in the drill's table. Every step that needed knowledge the runbook lacked is
fixed in self-hosting.md, not remembered.

### 6.2 What the drill can't check: a restored server sending again

The drill runs with `OUTBOUND_DELIVERY=false` and Stalwart in recovery
mode, so it never shows that a restored server federates and sends mail
once delivery is back on. That needs two servers that are not production.
`scripts/restore-federation-check.sh` does it on the two-server harness, in
lane 2 (not beside B2, which uses the same project), 30 min:

1. both servers up, accounts on both (the federation gate's setup phase);
2. B unreachable, A queues sends to B;
3. A's database dumped, dropped and restored;
4. A started with `OUTBOUND_DELIVERY=false`: for 45 s its queued rows and
   their attempts don't move, and B records no request;
5. A with delivery on: the queued sends arrive and B accepts A (the
   verify-retry phase); A's discovery names the same identity key
   throughout.

**Pass:** it exits 0.

Mail between two servers needs two Stalwarts and DNS: not covered here.
   The mail gate (B3) covers sending to an outside sink. Production's first
   real send (§8.6) covers a restored Stalwart's DKIM.

## 7. Phase F: master and CI

Local results are the gate, but `deploy.sh` refuses a commit without green
GitHub CI on master (one CI run, not reruns).

1. Merge the final tree into master in one PR. Its PR checks run static,
   rust and web. Read them before merging.
2. After the merge, master CI runs the browser and live jobs that only run
   there: chat-backup-browser,
   mail-browser, mail-gate, mail-domains-browser, chat-security-e2e.
   **Pass:** all green. A VM-only failure from §3 is settled here.
3. `scripts/publish-images.sh --push` from that clean master commit. It
   prints the release (CalVer) and the three image lines. Make any new ghcr
   package public in the GitHub UI.

About 60 min, mostly CI.

## 8. Phase G: deploy to kutup.dev and wipe

Only after §2–§7 pass and §0's U1–U4 are done. The steps follow
the deployment notes and `scripts/deploy.sh`'s header.

### 8.1 Before

- `ssh -i ~/_e/hetzner/key.txt root@kutupbulut.com` works.
- The disk has room for the three new images (about 2.6 GB a release): `df -h /`.
- Old release images are removed except the running one.
- Production's current `.env` is copied off the box, as the rollback copy.

### 8.2 The new `.env` (on the box, `/opt/kutup/.env`)

Edit a copy (`.env.new`) and check it with the new server before it is used
(8.3 does that through `deploy.sh --dry-run`).

| Setting | Value | Note |
|---|---|---|
| `BACKUP_S3_ENDPOINT`, `BACKUP_S3_BUCKET`, `BACKUP_S3_ACCESS_KEY`, `BACKUP_S3_SECRET_KEY`, `BACKUP_S3_REGION` | from U1 | the scripts refuse the data bucket and its key |
| `KUTUP_BACKUP_AGE_RECIPIENT` | `age1…` from U2 | public key only |
| `POSTGRES_APP_USER`, `POSTGRES_APP_PASSWORD` | `kutup_app`, `openssl rand -hex 32` | the wipe drops the database volume, so `postgres/initdb/10-app-role.sh` creates the role on first start; **no manual `CREATE ROLE`**. Only a deploy without `--wipe` would need `docker compose exec -T postgres psql -U kutup -d kutup -c "CREATE ROLE kutup_app LOGIN PASSWORD '…'"` |
| `KUTUP_CSP_ENFORCE` | 0 or 1 (U6, §5.4) | read by the frontend container |
| `OUTBOUND_DELIVERY` | `true` (or leave unset: true is the default) | false only in drills |
| `BACKGROUND_JOBS` | `true` (or unset) | false only in drills |
| `OPAQUE_SETUP_KEYS` | **a new list** for the clean slate: `1:<base64 of 32 random bytes>` | it also wraps every account data key (L1; there is no separate server data key variable). Offline copy (U5) before the stack starts |
| `ADMIN_ACCOUNT` | `admin:<new password>` | the password into `/root/kutup-admin-password.txt` |
| `MAIL_FORWARDING_KEYS`, `MAIL_DKIM_KEYS` | new values when those features are on at the wipe | each needs an offline copy |
| `CHAT_GROUPS` | U6 | |
| removed or renamed by W7 group 4 (settings namespaced) and the API pass | per their notes | `check-config` names any unknown or missing key |

Also on the box, before the wipe:
- **Disable the old nightly timer's target.** `kutup-backup.timer` now runs
  the new `backup-postgres.sh` against `BACKUP_S3_*`. Check that its unit
  runs from `/opt/kutup` and that `age` is installed on the host:
  `apt install age`.
- Stalwart's mail backup timer: the same, via `backup-stalwart.sh`.

### 8.3 Dry run

From the user's machine:

```sh
KUTUP_DEPLOY_HOST=root@kutupbulut.com KUTUP_DEPLOY_KEY=~/_e/hetzner/key.txt \
  scripts/deploy.sh <tag> --wipe --dry-run
```

**Pass:**
- CI is green for the tag on master;
- the images pull;
- check-config passes against the new `.env`;
- the bucket listing shows what the wipe deletes, with no backup prefix among it.

### 8.4 Ask, then wipe

Show the user the dry run's summary:
- the objects to delete;
- the backups kept;
- the tag;
- the new secrets (`ADMIN_ACCOUNT`, `OPAQUE_SETUP_KEYS`), which need their own copies.

Then ask, in so many words: "I'm about to wipe kutup.dev now: are you
confirming?" **Wait for the user's yes**.
Then:

```sh
KUTUP_DEPLOY_HOST=… scripts/deploy.sh <tag> --wipe
```

It backs up the old database first, to the old location under the old
`.env`'s settings; that backup is kept. Then it:
- drops the database volume;
- empties the data bucket except the backup prefixes;
- keeps `stalwart_data` (DKIM keys);
- starts the stack and restarts nginx;
- checks migrations, backend errors, Stalwart's setup, storage and every host.

About 20 min.

### 8.5 Right after

1. Sign in as the new admin (key wizard), set registration as U6 says, and
   create the user's account. The user signs in on their own devices.
2. In a browser that used the old kutup.dev: open each app. **Pass:** the
   "server was reset" notice, and no old local data (§4.3's check, in
   production).
3. `scripts/backup-postgres.sh` once by hand on the box. **Pass:** the dump
   lands in the U1 bucket; `GET /api/health/ready` answers 200 (it fails
   until a backup exists).
4. `docker compose run --rm --no-deps backend check-config`: no warning that
   the logs are not append-only (the app role is in force).
5. Remove old images except the new and the previous release; keep
   `amazon/aws-cli`.

### 8.6 First week

- **CSP reports:**
  `docker compose logs backend --since 24h | grep 'content security policy violation' | sed 's/.*violation//' | sort | uniq -c | sort -rn`,
  daily, sorted as §5.4 does. Enforce once only (a) remains and it is closed.
- **The restore drill E2** (§6.1) against the first nightly backup.
- **A real mail** from kutup.dev to an outside address (Gmail) and back:
  - DKIM, SPF and DMARC pass;
  - `MAIL_OUTSIDE_SENDING` is as the user set it.
- **Federation:** discovery answers at `https://kutup.dev/.well-known/kutup/federation.json`.

## 9. The record

Fill this in as the test runs: one row per step, with the date, the tree
SHA, the result, the duration and notes (failures, re-runs, VM-only
causes, the WASM table, the WebKit playback paths, the CSP sort). A fix to
the tree re-runs:
- every step of Phase A;
- any live gate whose area it touches (all of Phase B for a change that
  reaches federation, backup or the schema);
- the suites of the apps it touches.

| Step | Date | SHA | Result | Time | Notes |
|---|---|---|---|---|---|
| | | | | | |

## 10. Findings while writing this

- **F-1. 38 browser specs run nowhere.** They're in no suite and no CI job:
  - Drive: 18, 26, 27, 30, 47, 49, 50, 53, 70, 71;
  - Office, notes and whiteboards: 02, 03, 13, 19, 20, 21, 24, 29, 43, 45, 114;
  - Chat: 31, 37, 39, 41, 42, 46, 48, 72;
  - account, admin and the rest: 01, 28, 35, 44, 51, 52, 61, 73, 75.

  Done on this branch: `tests/e2e/suites/drive.txt`, `office-docs.txt`,
  `chat.txt` and `account-misc.txt` list them, C7 runs them, and CI's new
  `workspace-browser` job runs them on master and on demand (no PR
  minutes), beside the Mail browser job. Only the four two-server specs
  (B2's) and `screenshots` stay outside the suites.
- **F-2. self-hosting.md, "What a restore needs"**, lists
  `SERVER_DATA_KEYS (with L1)`. L1 decided against a second list: the
  account data keys are wrapped under `OPAQUE_SETUP_KEYS`
  (server-personal-data.md, "Where the key lives"). Done on this branch:
  the row is gone, and the `OPAQUE_SETUP_KEYS` row says what it also
  wraps.
- **F-3. "A restored server delivers again"** (§6.2) is now
  `scripts/restore-federation-check.sh` (written, not run until the test).
- **F-4. CI's single-server browser jobs run without the app role**, so
  `POSTGRES_APP_USER` is exercised only by the backup gate and the isolated
  e2e stack (Stack P here). A roadmap entry ("CI · browser specs on the
  server's own database role") keeps it.
- **F-5.** docs/plans/restore-drill-and-alerting.md is cited by
  self-hosting.md and server-personal-data.md but is not on `wipe/w7`; it
  comes into the final tree with plans PR #413.
