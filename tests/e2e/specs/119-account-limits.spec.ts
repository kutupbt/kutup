import { expect, test } from '@playwright/test'
import { appUrl, newAccount, signInAsAdmin } from '../fixtures/apps'

// An account's own limits (docs/plans/settings-registry.md): on the account's
// page an administrator gives it its own upload limit, sees where the value
// comes from, and gives it back the server's.

const MIB = 1024 * 1024

test("an account's own limit: set on its page, shown as its own, reset to the server's", async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await signInAsAdmin(context)
  const page = await context.newPage()
  try {
    const person = newAccount('lim119', 'unused')
    await page.goto(appUrl('account', '/admin/users/new'))
    await page.getByLabel('Username', { exact: true }).fill(person.username)
    await page.getByRole('button', { name: 'Create user' }).click()
    await expect(page.getByRole('heading', { name: 'User created' })).toBeVisible({ timeout: 30_000 })
    await page.getByRole('button', { name: 'Done' }).click()
    await page.goto(appUrl('account', '/admin/users'))
    await page.getByPlaceholder('Search by username or address').fill(person.username)
    await page.getByRole('row').filter({ hasText: person.username }).first().click()
    await page.waitForURL(/\/admin\/users\/[0-9a-f-]{36}$/)

    const row = page.getByTestId('admin-rate-limit-drive_upload_max_bytes')
    await expect(row.getByText('Largest upload (bytes)')).toBeVisible({ timeout: 30_000 })
    await expect(row.getByText(/^The server's/)).toBeVisible()
    const input = row.getByTestId('admin-rate-limit-drive_upload_max_bytes-value')
    const site = await input.inputValue()
    // Below its range: refused on the page.
    await input.fill('5')
    await expect(row.getByRole('alert')).toBeVisible()
    await expect(row.getByRole('button', { name: 'Save' })).toBeDisabled()

    await input.fill(String(MIB))
    await row.getByRole('button', { name: 'Save' }).click()
    await expect(row.getByText(`This account's own; the server's is ${site}`)).toBeVisible({ timeout: 15_000 })
    // Still its own after a reload.
    await page.reload()
    await expect(page.getByTestId('admin-rate-limit-drive_upload_max_bytes-value')).toHaveValue(String(MIB), { timeout: 30_000 })

    await page.getByTestId('admin-rate-limit-drive_upload_max_bytes-reset').click()
    await expect(page.getByTestId('admin-rate-limit-drive_upload_max_bytes-value')).toHaveValue(site, { timeout: 15_000 })
    await expect(page.getByTestId('admin-rate-limit-drive_upload_max_bytes').getByText(/^The server's/)).toBeVisible()

    // Gone with the account.
    await page.getByRole('button', { name: 'Delete account', exact: true }).click()
    const dialog = page.getByRole('alertdialog')
    await dialog.getByLabel(`Type ${person.username} to confirm`).fill(person.username)
    await dialog.getByRole('button', { name: 'Delete account', exact: true }).click()
    await page.waitForURL(/\/admin\/users$/)
  } finally {
    await context.close()
  }
})
