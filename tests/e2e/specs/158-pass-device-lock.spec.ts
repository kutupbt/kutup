import { expect, test, type Page } from '@playwright/test'
import { appUrl, newAccount, openDrive, registerAccount, submitThroughRateLimit } from '../fixtures/apps'
import { openItem } from '../fixtures/drive'
import { createVault, openPass } from '../fixtures/pass'

// One lock for Pass on the device (sync/deviceLock.ts): a vault locked in one
// tab is locked in every way in, a new tab and Drive included, and opens with
// the same unlock everywhere, the one the person set: a click when there is
// no PIN (never a password nobody chose), the PIN when there is one.

const PASSWORD = 'Deneme123*PassDeviceLock'

async function lockFromMenu(page: Page) {
  await page.getByRole('button', { name: 'Vault actions' }).click()
  await page.getByRole('menuitem', { name: 'Lock vault' }).click()
  await expect(page.getByRole('heading', { name: 'Vaults', exact: true })).toBeVisible()
}

/** Opens the vault from Drive, as a double-click on its file does. */
async function openFromDrive(page: Page, file: string) {
  await expect(page.getByText(file, { exact: true }).first()).toBeVisible({ timeout: 60_000 })
  await openItem(page, file)
  await expect(page).toHaveURL(/pass\..*\/v\//, { timeout: 60_000 })
}

test('pass: without a PIN, a locked vault opens with one click in its tab, a new tab and from Drive', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('pass158a', PASSWORD))
  const page = await context.newPage()
  await openPass(page)
  // The default: a random key, kept in the account (quick open).
  const vaultUrl = await createVault(page, 'Kişisel', null)
  const unlock = (p: Page) => p.getByRole('heading', { name: 'Unlock Kişisel' })
  const opened = (p: Page) => p.getByRole('heading', { name: 'Kişisel', exact: true, level: 1 })

  // Locked here: one click, not the account password.
  await lockFromMenu(page)
  await page.goto(vaultUrl)
  await expect(unlock(page)).toBeVisible({ timeout: 60_000 })
  await expect(page.getByRole('button', { name: 'Unlock with my sign-in' })).toBeVisible()
  await expect(page.getByLabel('Your Kutup password')).toBeHidden()

  // The same lock from Drive, in another tab: the same click, not opened
  // past the lock.
  const drive = await openDrive(context)
  await openFromDrive(drive, 'Kişisel.kdbx')
  await expect(unlock(drive)).toBeVisible({ timeout: 60_000 })
  await drive.getByRole('button', { name: 'Unlock with my sign-in' }).click()
  await expect(opened(drive)).toBeVisible({ timeout: 60_000 })

  // Unlocked there: open here too after a reload.
  await page.reload()
  await expect(opened(page)).toBeVisible({ timeout: 60_000 })

  // Locked again in the Drive tab: the other tab closes it at once.
  await lockFromMenu(drive)
  await expect(page.getByRole('heading', { name: 'Vaults', exact: true }).or(unlock(page))).toBeVisible({ timeout: 30_000 })
  await expect(opened(page)).toBeHidden()

  // A new tab meets the lock too.
  const fresh = await context.newPage()
  await fresh.goto(vaultUrl)
  await expect(unlock(fresh)).toBeVisible({ timeout: 60_000 })
  await fresh.getByRole('button', { name: 'Unlock with my sign-in' }).click()
  await expect(opened(fresh)).toBeVisible({ timeout: 60_000 })
  await context.close()
})

test('pass: with a PIN, a vault locked in one tab asks for the PIN when opened from Drive', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('pass158b', PASSWORD))
  const page = await context.newPage()
  await openPass(page)
  const vaultUrl = await createVault(page, 'Kişisel', null)

  // A PIN set: the default after a lock becomes the PIN.
  await page.goto(appUrl('pass'))
  await page.getByRole('combobox', { name: 'After a lock, open vaults with' }).click()
  await page.getByRole('option', { name: 'My PIN' }).click()
  const dialog = page.getByRole('dialog', { name: 'Set a PIN' })
  await dialog.getByLabel('New PIN (six digits)').fill('482915')
  await dialog.getByLabel('The PIN again').fill('482915')
  await submitThroughRateLimit(page, 'Set PIN', page.getByText('Your account has a PIN.'), () =>
    dialog.getByLabel('Your Kutup password').fill(PASSWORD),
  )
  await expect(dialog).toBeHidden()

  await page.goto(vaultUrl)
  await expect(page.getByRole('heading', { name: 'Kişisel', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await lockFromMenu(page)

  // From Drive, in another tab: the PIN, not the vault.
  const drive = await openDrive(context)
  await openFromDrive(drive, 'Kişisel.kdbx')
  await expect(drive.getByRole('heading', { name: 'Unlock Kişisel' })).toBeVisible({ timeout: 60_000 })
  await expect(drive.getByLabel('PIN', { exact: true })).toBeVisible()
  await expect(drive.getByRole('heading', { name: 'Kişisel', exact: true, level: 1 })).toBeHidden()
  await drive.getByLabel('PIN', { exact: true }).fill('482915')
  await expect(drive.getByRole('heading', { name: 'Kişisel', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await context.close()
})
