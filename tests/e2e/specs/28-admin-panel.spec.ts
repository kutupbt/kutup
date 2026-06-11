import { test, expect, type Page, type BrowserContext } from '@playwright/test'
import { signInOrBootstrap, ADMIN_EMAIL } from '../fixtures/auth'

// E2E coverage for the desktop admin panel (PR #28 — feat/admin-backend):
//   - Overview tab renders the KPI grid + encryption banner.
//   - The break-glass admin row is badged and its destructive ⋯ actions
//     are disabled (the backend would 403 them anyway).
//   - The create → promote → demote → delete user lifecycle works end-to-end
//     through the real API.
//   - The Disable-2FA menu item is correctly disabled for a user with no 2FA.
//   - The Settings → Storage card renders real, formatted capacity numbers.
//
// Serial + a shared signed-in page: the suite mutates shared DB state and
// the E2EE login (Argon2id) is ~1s — re-authenticating per test is wasteful.
test.describe.serial('admin panel', () => {
  let ctx: BrowserContext
  let page: Page

  test.beforeAll(async ({ browser }) => {
    ctx = await browser.newContext({ ignoreHTTPSErrors: true })
    page = await signInOrBootstrap(ctx)
    await page.goto('/admin')
    // AdminSidebar is the tell-tale that the admin shell mounted.
    await expect(page.locator('aside')).toBeVisible({ timeout: 30_000 })
  })

  test.afterAll(async () => {
    await ctx.close()
  })

  /** Switch admin tab via the sidebar nav. */
  async function gotoTab(name: 'Overview' | 'Users' | 'Settings') {
    await page.locator('aside').getByRole('button', { name, exact: true }).click()
  }

  test('Overview renders the KPI grid + encryption banner', async () => {
    await gotoTab('Overview')
    await expect(page.getByText('Total users').first()).toBeVisible()
    await expect(page.getByText('End-to-end encrypted').first()).toBeVisible()
  })

  test('break-glass admin row is badged and its destructive actions are disabled', async () => {
    await gotoTab('Users')
    const row = page.locator('tr', { hasText: ADMIN_EMAIL }).first()
    await expect(row).toBeVisible({ timeout: 15_000 })
    // The break-glass badge.
    await expect(row.getByText('Break-glass', { exact: true })).toBeVisible()

    // Open the row's ⋯ menu — demote / disable / delete must be disabled.
    await row.getByRole('button', { name: 'Actions' }).click()
    const menu = page.getByRole('menu')
    await expect(menu).toBeVisible()
    await expect(menu.getByRole('menuitem', { name: 'Remove admin role' })).toBeDisabled()
    await expect(menu.getByRole('menuitem', { name: 'Disable account' })).toBeDisabled()
    await expect(menu.getByRole('menuitem', { name: 'Delete permanently' })).toBeDisabled()
    // Edit quota stays available on the break-glass admin.
    await expect(menu.getByRole('menuitem', { name: 'Edit quota' })).toBeEnabled()
    await page.keyboard.press('Escape')
  })

  test('create → promote → demote → delete a user', async () => {
    const stamp = Date.now()
    const email = `e2e-admin-${stamp}@kutup.local`
    const username = `e2eadmin${stamp}` // lowercase digits — satisfies ^[a-z0-9_-]{3,32}$

    await gotoTab('Users')

    // ── Create ──────────────────────────────────────────────────────
    await page.getByRole('button', { name: 'Create user' }).first().click()
    const dialog = page.getByRole('dialog')
    await expect(dialog).toBeVisible()
    await dialog.getByLabel('Email').fill(email)
    await dialog.getByLabel('Username').fill(username)
    await dialog.getByLabel('Temporary password').fill('TempPass-e2e-123')
    await dialog.getByRole('button', { name: 'Create user' }).click()
    await expect(dialog).toBeHidden({ timeout: 15_000 })

    // Search to isolate the new row regardless of pagination.
    const search = page.getByPlaceholder(/Search by email/i)
    await search.fill(email)
    const row = page.locator('tr', { hasText: email }).first()
    await expect(row).toBeVisible({ timeout: 15_000 })
    // Fresh user has no 2FA → the Disable-2FA action is disabled.
    await row.getByRole('button', { name: 'Actions' }).click()
    await expect(page.getByRole('menuitem', { name: 'Disable 2FA' })).toBeDisabled()
    await page.keyboard.press('Escape')

    // ── Promote ─────────────────────────────────────────────────────
    await row.getByRole('button', { name: 'Actions' }).click()
    await page.getByRole('menuitem', { name: 'Make admin' }).click()
    await page.getByRole('alertdialog').getByRole('button', { name: 'Make admin' }).click()
    await expect(row.getByText('Admin', { exact: true })).toBeVisible({ timeout: 15_000 })

    // ── Demote ──────────────────────────────────────────────────────
    await row.getByRole('button', { name: 'Actions' }).click()
    await page.getByRole('menuitem', { name: 'Remove admin role' }).click()
    await page.getByRole('alertdialog').getByRole('button', { name: 'Remove admin role' }).click()
    await expect(row.getByText('Admin', { exact: true })).toBeHidden({ timeout: 15_000 })

    // ── Delete (cleanup) ────────────────────────────────────────────
    await row.getByRole('button', { name: 'Actions' }).click()
    await page.getByRole('menuitem', { name: 'Delete permanently' }).click()
    await page.getByRole('alertdialog').getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(page.locator('tr', { hasText: email })).toHaveCount(0, { timeout: 15_000 })

    // ── Audit trail ─────────────────────────────────────────────────
    // The lifecycle above must be visible in the Recent-activity feed.
    // The delete row resolves the target from the payload snapshot (the
    // account no longer exists), proving the trail outlives the user.
    await gotoTab('Overview')
    const activityCard = page.getByTestId('admin-activity')
    await expect(activityCard.getByText(`deleted user ${email}`).first()).toBeVisible({
      timeout: 15_000,
    })
    await expect(activityCard.getByText(`created user ${email}`).first()).toBeVisible()
  })

  test('Settings → Storage card renders real formatted capacity', async () => {
    await gotoTab('Settings')
    await expect(page.getByText('Storage backend').first()).toBeVisible()
    await expect(page.getByText('SeaweedFS · S3-compatible').first()).toBeVisible()
    // The storage-used row: "<used> of <total> · <free> free" — unit-agnostic
    // (the deterministic TB/PB check lives in frontend format.test.ts).
    await expect(
      page.getByText(/\d[\d.,]*\s(B|KB|MB|GB|TB|PB)\b.*\bfree\b/).first(),
    ).toBeVisible()
  })
})
