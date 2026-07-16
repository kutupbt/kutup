# kutup e2e tests

Playwright tests against the local stack at `https://localhost:38443`. Each spec assumes the stack is up; specs that need a fresh DB call `wipeStack()` from `fixtures/stack.ts` (a `docker compose down -v` + bind-mount cleanup, ~30 s).

## Setup

```sh
cd tests/e2e
npm install
npx playwright install chromium
```

## Run

```sh
npx playwright test                      # all
npx playwright test 03-office-saveChanges  # one spec
npx playwright test --grep '@race'        # by tag (when added)
npx playwright test --headed              # watch in a browser
```

Reports: `playwright-report/index.html` (gitignored).

## Layout

- `playwright.config.ts` — shared config; `fullyParallel: false, workers: 1` because the specs share a single backend stack.
- `fixtures/auth.ts` — `signInOrBootstrap()` drives the bootstrap → first-login → drive flow; `attachCollabLogs()` collects `[kutup-bridge]` / `[office]` console output.
- `fixtures/stack.ts` — `wipeStack()` resets postgres + seaweedfs to a fresh bootstrap admin.
- `specs/01-…` regression for the FirstLogin /drive bounce bug (commit `bbbb8b1`).
- `specs/02-…` regression for the note initial-seed duplication (commit `be712d9`).
- `specs/03-…` regression for the OnlyOffice saveChanges JSON.parse fix (commit `21a7af3`).
- `specs/04-…` happy-path two-tab xlsx sync.
- `specs/05-…` race-condition tests for fast simultaneous tab-open. Currently failing — that's the open bug.
- `specs/31-chat.spec.ts` registers two accounts, links a second install, proves
  Note to Self reaches it as encrypted outgoing history, exchanges messages
  both ways, and proves acked history survives an IndexedDB-backed reload.
  Rebuild the frontend image first so `/chat-wasm/*` contains the current
  generated module.
