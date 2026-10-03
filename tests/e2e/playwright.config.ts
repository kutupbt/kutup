import { defineConfig, devices } from '@playwright/test'
import { tmpdir } from 'node:os'
import { resolve } from 'node:path'

import { allOrigins, appOrigin } from './fixtures/apps'

// kutup e2e: runs against a running stack whose apps live one per hostname,
// https://{app}.localhost:38443 by default (fixtures/apps.ts; override with
// E2E_APP_ORIGIN and, for two-server specs, E2E_SECONDARY_APP_ORIGIN).
// Tests assume the stack is already up.
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
    // Relative navigation opens the account app; specs name other apps with
    // appUrl().
    baseURL: appOrigin('account'),
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
      use: {
        ...devices['Desktop Chrome'],
        channel: 'chromium',
        launchOptions: { args: browserArgs() },
      },
    },
  ],
})

/**
 * Test hostnames outside `localhost` (the federation stack's `*.a.test`)
 * resolve to this machine, and their plain-HTTP origins count as secure
 * contexts, which the apps' Web Crypto, service worker and clipboard need.
 */
function browserArgs(): string[] {
  const origins = allOrigins().map((origin) => new URL(origin))
  const foreign = origins.filter((url) => url.hostname !== 'localhost' && !url.hostname.endsWith('.localhost'))
  const args: string[] = []
  // A local stack's self-signed certificate: Playwright's ignoreHTTPSErrors
  // does not cover service-worker scripts, which ONLYOFFICE registers.
  if (process.env.E2E_TRUST_LOCAL_CERT === '1') args.push('--ignore-certificate-errors')
  if (foreign.length > 0) {
    const rules = [...new Set(foreign.map((url) => url.hostname))].map((host) => `MAP ${host} 127.0.0.1`)
    args.push(`--host-resolver-rules=${rules.join(', ')}`)
  }
  const insecure = foreign.filter((url) => url.protocol === 'http:').map((url) => url.origin)
  if (insecure.length > 0) args.push(`--unsafely-treat-insecure-origin-as-secure=${insecure.join(',')}`)
  return args
}
