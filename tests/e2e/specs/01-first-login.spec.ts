import { test, expect } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'
import { wipeStack } from '../fixtures/stack'

// Regression for commit bbbb8b1.
//
// Bug: FirstLogin.tsx re-read sessionStorage on every render, so after
// handleConfirmMnemonic cleared `setup_token` and called navigate('/drive'),
// a final pre-unmount render observed the empty token and the existing
// `if (!setupToken) navigate('/login')` effect bounced the freshly-
// authenticated user away from /drive. Fix: snapshot once via useState lazy
// init.
test.describe('first-login flow', () => {
  test.beforeAll(() => wipeStack())

  test('lands on /drive after mnemonic confirm and stays there', async ({ context }) => {
    const page = await signInOrBootstrap(context)

    // signInOrBootstrap waits for /drive; assert we're still there a moment
    // later — that's where the bug used to bounce us back to /login.
    await page.waitForTimeout(2_000)
    expect(page.url()).toContain('/drive')

    // Drive's nav must be rendered (proves ProtectedRoute didn't redirect).
    await expect(page.locator('button:has-text("New")').first()).toBeVisible()
    await expect(page.locator('button:has-text("Sign out")').first()).toBeVisible()
  })
})
