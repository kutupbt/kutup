import { test, expect } from '@playwright/test'
import { signInOrBootstrap, ADMIN_EMAIL, BOOTSTRAP_PW, NEW_PW } from '../fixtures/auth'

// E2E coverage for the regular login flow (separate from first-login):
//   1. Bootstrap the admin once (signInOrBootstrap drives it).
//   2. Sign out.
//   3. Wrong password → 401, stays on /login.
//   4. Right password (NEW_PW from first-login) → /drive.
//
// This is the security-critical path: any regression that lets a wrong
// password through, or that masks a 401 as a session-expiry retry, would
// surface here.
test.describe('login (post-bootstrap)', () => {
  // Drive once through first-login so the admin's NEW_PW is set.
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true })
    await signInOrBootstrap(ctx)
    await ctx.close()
  })

  test('rejects wrong password (401)', async ({ context }) => {
    const page = await context.newPage()
    await page.goto('/login')
    await page.locator('input[type=email]').fill(ADMIN_EMAIL)
    await page.locator('input[type=password]').fill(BOOTSTRAP_PW) // not the new pw anymore
    const respPromise = page.waitForResponse(
      (r) => r.url().includes('/auth/login') && r.request().method() === 'POST',
      { timeout: 15_000 },
    )
    await page.locator('button[type=submit]').click()
    const resp = await respPromise
    expect(resp.status()).toBe(401)
    // Must still be on /login.
    await page.waitForTimeout(500)
    expect(page.url()).toContain('/login')
  })

  test('accepts the new password and lands on /drive', async ({ context }) => {
    const page = await context.newPage()
    await page.goto('/login')
    await page.locator('input[type=email]').fill(ADMIN_EMAIL)
    await page.locator('input[type=password]').fill(NEW_PW)
    await page.locator('button[type=submit]').click()
    await page.waitForURL(/\/drive/, { timeout: 30_000 })
    expect(page.url()).toContain('/drive')
  })

  test('rejects unknown email (stays on /login)', async ({ context }) => {
    const page = await context.newPage()
    await page.goto('/login')
    await page.locator('input[type=email]').fill('nobody@example.com')
    await page.locator('input[type=password]').fill('AnyPassword123')
    await page.locator('button[type=submit]').click()
    // The preflight returns deterministic-fake salts then login bcrypts a
    // fake hash to keep timing constant. End result: 401 from /api/auth/login.
    // Generous wait — Argon2id KDF (3 iter / 64MB) takes ~1s in browser.
    await page.waitForTimeout(8_000)
    expect(page.url(), 'must stay on /login for unknown email').toContain('/login')
  })
})
