import { defineConfig, devices } from '@playwright/test'

// kutup e2e: runs against the local stack at https://localhost:38443.
// Tests assume the stack is already up; the wipe-stack fixture (bin/reset)
// is invoked manually between specs that need a fresh DB.
export default defineConfig({
  testDir: './specs',
  testMatch: '**/*.spec.ts',
  // Specs that mutate global stack state must NOT run in parallel — each
  // wipes the postgres volume and goes through bootstrap. Within a single
  // spec, sub-tests can run sequentially.
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  timeout: 120_000,
  expect: { timeout: 15_000 },
  use: {
    baseURL: 'https://localhost:38443',
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
})
