# Kutup browser tests

Playwright tests the real web apps, Rust/WASM crypto, IndexedDB, API,
PostgreSQL, and SeaweedFS. Kutup serves one app per hostname (account, drive,
chat, photos, maps, office), so a server is described by an origin template:
`E2E_APP_ORIGIN` defaults to `https://{app}.localhost:38443`, and two-server
specs also read `E2E_SECONDARY_APP_ORIGIN`. `*.localhost` resolves to this
machine in Chromium; for other test hostnames (`*.a.test`) the config maps them
to 127.0.0.1 and treats their plain-HTTP origins as secure contexts. Tests
assume the selected stack is already healthy.

Node-side calls (health and preflight probes) cannot resolve test hostnames,
so two-server runs also set `E2E_API_URL` / `E2E_SECONDARY_API_URL` to the
edges and `E2E_DOMAIN` / `E2E_SECONDARY_DOMAIN` to the federation domains.
`scripts/test-chat-federation.sh` sets all of them.

Playwright is intentionally configured with `fullyParallel: false`, one worker,
and `retries: 0`. Specs share or deliberately reset backend state, and a retry
must never hide a recovery, crypto, or convergence failure.

The Chromium project uses the full browser's headless mode. This remains
installed by `playwright install chromium` and avoids the standalone legacy
headless shell, which can SIGTRAP under OnlyOffice's repeated nested
canvas/worker load.

## Install

```sh
npm ci --prefix tests/e2e
npx --prefix tests/e2e playwright install chromium
```

CI uses `playwright install --with-deps chromium` on a fresh Ubuntu runner.

## Start an isolated single-server stack

The checked-in Nginx requires a certificate. For local testing only:

```sh
mkdir -p nginx/certs
openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
  -keyout nginx/certs/privkey.pem -out nginx/certs/fullchain.pem \
  -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1
export COMPOSE_PROJECT_NAME=kutup-e2e
export COMPOSE_FILE=docker-compose.yml:tests/e2e/docker-compose.isolated.yml
export KUTUP_E2E_DATA_DIR=/tmp/kutup-e2e-data
export KUTUP_HTTP_PORT=39080
export KUTUP_HTTPS_PORT=39443
for app in account drive chat office maps photos; do
  export "KUTUP_$(echo "$app" | tr a-z A-Z)_URL=https://$app.localhost:39443"
done
export E2E_APP_ORIGIN='https://{app}.localhost:39443'
docker compose up --detach --build --wait
curl --fail --insecure https://localhost:39443/api/auth/settings
```

The Nginx health check and bounded `curl` probe are the readiness boundary. Do
not replace them with a fixed sleep. The frontend image bakes the production
bundle and generated WASM, so rebuild it after frontend, Chat-core, or crypto
changes. The override redirects SeaweedFS bind mounts away from repository data;
the Compose project name separately isolates named volumes and containers, and
the alternate host ports allow the test stack to coexist with a development
stack using the defaults.

## Run

From `tests/e2e`:

```sh
npm exec -- playwright test                         # all single-stack specs
npm exec -- playwright test specs/03-office-saveChanges.spec.ts
npm exec -- playwright test specs/33-chat-history-recovery.spec.ts --project=chromium
npm exec -- playwright test specs/35-polar-workspace-accessibility.spec.ts --project=chromium
npm exec -- playwright test --headed
```

Every spec registers its own fresh accounts, so specs need no database reset
and can run in any order against one stack. Admin specs sign in as the
isolated stack's break-glass administrator (`docker-compose.isolated.yml`);
its first sign-in replaces the bootstrap password through the key wizard. Run
one Playwright process at a time: runs share `test-results/`, which each run
clears when it starts.

A local stack uses a self-signed certificate, which Playwright's
`ignoreHTTPSErrors` does not extend to service-worker scripts (ONLYOFFICE
registers one); `E2E_TRUST_LOCAL_CERT=1` makes Chromium accept it.

Normal local runs write the HTML report to `playwright-report/` and per-test
artifacts to `test-results/`; both are ignored by Git.

## Required Chat backup gates

Use the repository scripts from the workspace root. They own disposable Compose
projects and always tear them down:

```sh
./scripts/test-chat-backup-integration.sh
./scripts/test-chat-federation.sh
```

`test-chat-backup-integration.sh` runs the live backup endpoint lifecycle
against isolated PostgreSQL and SeaweedFS, fixed-cutoff mailbox and temporary
media retention, account purge, object cleanup, and exact charged-Chat-byte
release.

`test-chat-federation.sh` builds and starts the two-server `a.test`/`b.test`
topology, exercises API setup and durable retry across restart, scans
destination metadata, and then runs:

- spec 25: resumable encrypted tus upload;
- spec 32: Direct and exhaustive MLS security/media scenarios; and
- spec 34: two-account Direct/MLS/media browser-loss recovery, server restart,
  account-local backup proof, lazy media, and new post-restore protocol state.

Spec 33 is the required single-server clean-browser recovery gate. It uses a
new browser context without copied cookies, sessions, storage, or IndexedDB;
verifies automatic Note-to-Self history/media restoration and reload
persistence; and proves restore alone emits no receipt, mailbox acknowledgement,
or device-transfer API activity.

Run these locally before requesting or rerunning GitHub CI. GitHub is final
confirmation of a clean runner, not the first reproduction environment.

## Sensitive-artifact mode

Backup and security tests handle recovery phrases, tokens, ciphertext, account
identifiers, and opaque capabilities. Set:

```sh
KUTUP_E2E_SAFE_ARTIFACTS=1 \
KUTUP_E2E_DIAGNOSTICS_DIR=sanitized-results \
  npm exec -- playwright test specs/33-chat-history-recovery.spec.ts --project=chromium
```

This selects `safe-reporter.ts`, disables traces, screenshots, videos, and raw
page/network captures, and uses only static spec locations plus allow-listed
durable phase names. On stack failure,
`scripts/collect-chat-e2e-diagnostics.sh` writes sanitized aggregate service,
checkpoint, and error-category counts. It must never retain keys, phrases,
tokens, ciphertext, capabilities, digests, or stable user identifiers.

CI uploads only `tests/e2e/sanitized-results/**` for these jobs. If a failure is
not explained by the safe checkpoint, improve the allow-listed diagnostics and
reproduce locally; do not enable secret-bearing raw artifacts.

## Layout

- `playwright.config.ts`: shared one-worker, zero-retry config and safe-artifact
  selection.
- `safe-reporter.ts`, `safe-diagnostics.ts`: allow-listed output for sensitive
  Chat/backup runs.
- `fixtures/apps.ts`: app origins, account registration, first sign-in and
  administrator sign-in through the account app, and opening Drive.
- `fixtures/chat.ts`: Chat helpers (open, settings, conversations, messages,
  reactions, edits, groups, attachments, backup state).
- `fixtures/drive.ts`: Drive items and their menus, folders, notes and the
  note editor.
- `fixtures/office.ts`: ONLYOFFICE files, readiness from the bridge's log,
  sent and applied changes, and the cross-origin editor frame.
- `fixtures/whiteboard.ts`: whiteboards through Excalidraw's API.
- spec 01: an administrator-created account's first sign-in; wrong password
  and unknown email read the same.
- spec 02: note collaboration: a single seed, simultaneous opening, several
  tabs.
- specs 03, 04, 13, 19: office editing and reload, collaboration and
  cursors, formatting, and version history, in documents, sheets and slides.
- specs 18, 26, 27, 30: Drive rename, byte-exact download, folder upload,
  and trash.
- specs 20, 21, 24: whiteboard versions and restore, collaboration with
  images, and image storage accounting.
- spec 25: resumable encrypted tus upload into Drive.
- spec 28: administration: users, the break-glass admin's protections,
  roles, temporary passwords, wipe, activity, settings.
- spec 29: two people editing a note in a shared folder.
- spec 31: local Chat, linked-device transcripts, Note to Self, active
  installation review/rename/revoke, immutable numeric routing IDs, and
  durable IndexedDB reload.
- spec 32: two-server Direct/MLS, governance, anonymous media, linked device,
  replay, metadata, and restart security.
- spec 33: single-server automatic clean-browser Chat backup recovery and
  focused protected/unavailable media.
- spec 34: complete two-server browser-loss recovery matrix.
- spec 35: every app's sign-in and signed-in views at phone and desktop
  widths, both themes: one `main`, no page overflow, no serious/critical axe
  findings.
- spec 36: a group chat on a server with no federation settings.
- `screenshots.spec.ts`: refreshes the README images; runs only with
  `KUTUP_README_SCREENSHOTS=1`.
