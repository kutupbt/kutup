import { defineConfig, devices } from '@playwright/test'
import { tmpdir } from 'node:os'
import { resolve } from 'node:path'

// kutup e2e: runs against the local stack at https://localhost:38443
// (override with E2E_BASE_URL when the stack is on a different port).
// Tests assume the stack is already up; the wipe-stack fixture (bin/reset)
// is invoked manually between specs that need a fresh DB.
const BASE_URL = process.env.E2E_BASE_URL ?? 'https://localhost:38443'
const SAFE_ARTIFACTS = process.env.KUTUP_E2E_SAFE_ARTIFACTS === '1'
if (SAFE_ARTIFACTS) process.env.PLAYWRIGHT_NO_COPY_PROMPT = '1'

export default defineConfig({
  testDir: './specs',
  testMatch: '**/*.spec.ts',
  // Specs that mutate global stack state must NOT run in parallel — each
  // wipes the postgres volume and goes through bootstrap. Within a single
  // spec, sub-tests can run sequentially.
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: SAFE_ARTIFACTS
    ? './safe-reporter.ts'
    : process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  outputDir: SAFE_ARTIFACTS
    ? resolve(tmpdir(), `kutup-sensitive-e2e-${process.env.GITHUB_RUN_ID ?? 'local'}`)
    : 'test-results',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  use: {
    baseURL: BASE_URL,
    ignoreHTTPSErrors: true,
    // Security and backup CI handles recovery phrases, bearer tokens, opaque
    // archives, and account identifiers. Those jobs persist allow-listed
    // checkpoints/counts instead of raw browser or network captures.
    trace: SAFE_ARTIFACTS ? 'off' : 'retain-on-failure',
    screenshot: SAFE_ARTIFACTS ? 'off' : 'only-on-failure',
    video: SAFE_ARTIFACTS ? 'off' : 'retain-on-failure',
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
  },
  projects: [
    {
      name: 'chromium',
      // Use Chromium's full-browser headless mode. The legacy standalone
      // chrome-headless-shell process can SIGTRAP while repeatedly loading
      // OnlyOffice's nested canvas/worker stack in a long zero-retry run.
      // `playwright install chromium` provides this binary alongside the
      // shell, so local and CI installation commands remain unchanged.
      use: { ...devices['Desktop Chrome'], channel: 'chromium' },
    },
  ],
})
