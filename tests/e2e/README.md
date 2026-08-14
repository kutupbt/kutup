# Kutup browser tests

Playwright tests the real web application, Rust/WASM crypto, IndexedDB, API,
PostgreSQL, and SeaweedFS. The ordinary single-server suite targets
`https://localhost:38443`; set `E2E_BASE_URL` for another edge. Tests assume the
selected stack is already healthy.

Playwright is intentionally configured with `fullyParallel: false`, one worker,
and `retries: 0`. Specs share or deliberately reset backend state, and a retry
must never hide a recovery, crypto, or convergence failure.

## Install

```sh
npm ci --prefix tests/e2e
npx --prefix tests/e2e playwright install chromium
```

CI uses `playwright install --with-deps chromium` on a fresh Ubuntu runner.

## Start the single-server stack

The checked-in Nginx requires a certificate. For local testing only:

```sh
mkdir -p nginx/certs
openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
  -keyout nginx/certs/privkey.pem -out nginx/certs/fullchain.pem \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1
docker compose up --detach --build --wait
curl --fail --insecure https://localhost:38443/api/auth/settings
```

The Nginx health check and bounded `curl` probe are the readiness boundary. Do
not replace them with a fixed sleep. The frontend image bakes the production
bundle and generated WASM, so rebuild it after frontend, Chat-core, or crypto
changes.

## Run

From `tests/e2e`:

```sh
npm exec -- playwright test                         # all single-stack specs
npm exec -- playwright test specs/03-office-saveChanges.spec.ts
npm exec -- playwright test specs/33-chat-history-recovery.spec.ts --project=chromium
npm exec -- playwright test --headed
```

Specs that need a clean database call `wipeStack()` from `fixtures/stack.ts`.
It performs a Compose teardown with volumes and bind-mount cleanup, then boots a
fresh break-glass account. Do not run a destructive reset against a development
stack containing data you want to keep.

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
- `fixtures/auth.ts`: registration/bootstrap/login helpers and collaboration
  console attachment for ordinary non-sensitive specs.
- `fixtures/stack.ts`: destructive fresh-stack fixture for isolated specs.
- specs 01–30: onboarding, collaboration, office, whiteboard, upload/download,
  admin, sharing, and trash regressions.
- spec 31: local Chat, linked-device transcripts, Note to Self, and durable
  IndexedDB reload.
- spec 32: two-server Direct/MLS, governance, anonymous media, linked device,
  replay, metadata, and restart security.
- spec 33: single-server automatic clean-browser Chat backup recovery and
  focused protected/unavailable media.
- spec 34: complete two-server browser-loss recovery matrix.
