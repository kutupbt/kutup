import { expect, test, type Page } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { createVault, openPass } from '../fixtures/pass'

const PASSWORD = 'Deneme123*PassPinAccount'
const VAULT_PASSWORD = 'kasa-parolası-çğ-151'

async function lockVault(page: Page, vaultUrl: string) {
  await page.getByRole('button', { name: 'Vault actions' }).click()
  await page.getByRole('menuitem', { name: 'Lock vault' }).click()
  await expect(page.getByRole('heading', { name: 'Vaults', exact: true })).toBeVisible()
  await page.goto(vaultUrl)
  await expect(page.getByRole('heading', { name: 'Unlock Kişisel' })).toBeVisible({ timeout: 60_000 })
}

test('pass: a PIN set with the account password opens locked vaults; three wrong PINs sign out', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('pass151', PASSWORD))
  const page = await context.newPage()
  await openPass(page)
  await createVault(page, 'Kişisel', VAULT_PASSWORD)
  const vaultUrl = page.url()

  // Choosing the PIN asks for one first, with the account password.
  await page.goto(appUrl('pass'))
  await page.getByRole('combobox', { name: 'After a lock, open vaults with' }).click()
  await page.getByRole('option', { name: 'My PIN' }).click()
  const dialog = page.getByRole('dialog', { name: 'Set a PIN' })
  await dialog.getByLabel('Your Kutup password').fill(PASSWORD)
  // Digits only.
  await dialog.getByLabel('New PIN (six digits)').fill('24a6')
  await expect(dialog.getByLabel('New PIN (six digits)')).toHaveValue('246')
  await dialog.getByLabel('New PIN (six digits)').fill('246802')
  await dialog.getByLabel('The PIN again').fill('246801')
  await expect(dialog.getByText('The two PINs differ.')).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Set PIN' })).toBeDisabled()
  await dialog.getByLabel('The PIN again').fill('246802')
  await dialog.getByRole('button', { name: 'Set PIN' }).click()
  await expect(dialog).toBeHidden({ timeout: 30_000 })
  await expect(page.getByText('Your account has a PIN.')).toBeVisible()
  await expect(page.getByRole('combobox', { name: 'After a lock, open vaults with' })).toHaveText('My PIN')

  // Locked: the PIN opens it; the sixth digit sends it.
  await page.goto(vaultUrl)
  await expect(page.getByRole('heading', { name: 'Kişisel', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await lockVault(page, vaultUrl)
  await page.getByLabel('PIN', { exact: true }).fill('111111')
  await expect(page.getByText('Wrong PIN. 2 more tries, then you are signed out.')).toBeVisible({ timeout: 30_000 })
  await page.getByLabel('PIN', { exact: true }).fill('246802')
  await expect(page.getByRole('heading', { name: 'Kişisel', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })

  // Three wrong PINs in a row end the sign-in.
  await lockVault(page, vaultUrl)
  await page.getByLabel('PIN', { exact: true }).fill('111111')
  await expect(page.getByText('Wrong PIN. 2 more tries, then you are signed out.')).toBeVisible({ timeout: 30_000 })
  await page.getByLabel('PIN', { exact: true }).fill('222222')
  await expect(page.getByText('Wrong PIN. 1 more try, then you are signed out.')).toBeVisible({ timeout: 30_000 })
  await page.getByLabel('PIN', { exact: true }).fill('333333')
  await expect(page).toHaveURL(/account\..*\/(login|authorize)/, { timeout: 60_000 })
  await context.close()
})

test('pass: the PIN is removed with the account password, and a removed PIN falls back to the password', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('pass151b', PASSWORD))
  const page = await context.newPage()
  await openPass(page)
  await createVault(page, 'Kişisel', VAULT_PASSWORD)
  const vaultUrl = page.url()

  await page.goto(appUrl('pass'))
  await page.getByRole('combobox', { name: 'After a lock, open vaults with' }).click()
  await page.getByRole('option', { name: 'My PIN' }).click()
  const set = page.getByRole('dialog', { name: 'Set a PIN' })
  await set.getByLabel('Your Kutup password').fill(PASSWORD)
  await set.getByLabel('New PIN (six digits)').fill('135790')
  await set.getByLabel('The PIN again').fill('135790')
  await set.getByRole('button', { name: 'Set PIN' }).click()
  await expect(set).toBeHidden({ timeout: 30_000 })

  // Removed from a second tab (as another device would), while this one is locked.
  await page.goto(vaultUrl)
  await expect(page.getByRole('heading', { name: 'Kişisel', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await lockVault(page, vaultUrl)
  const other = await context.newPage()
  await other.goto(appUrl('pass'))
  await other.getByRole('button', { name: 'Remove PIN' }).click()
  const remove = other.getByRole('dialog', { name: 'Remove the PIN' })
  await remove.getByLabel('Your Kutup password').fill('not-my-password')
  await remove.getByRole('button', { name: 'Remove PIN' }).click()
  await expect(remove.getByText('That is not your Kutup password.')).toBeVisible({ timeout: 30_000 })
  await remove.getByLabel('Your Kutup password').fill(PASSWORD)
  await remove.getByRole('button', { name: 'Remove PIN' }).click()
  await expect(remove).toBeHidden({ timeout: 30_000 })
  await expect(other.getByRole('combobox', { name: 'After a lock, open vaults with' })).toHaveText('My Kutup password')
  await other.close()

  await page.getByLabel('PIN', { exact: true }).fill('135790')
  await expect(page.getByText(/The PIN was removed/)).toBeVisible({ timeout: 30_000 })
  await page.getByLabel('Your Kutup password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Unlock with my password' }).click()
  await expect(page.getByRole('heading', { name: 'Kişisel', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await context.close()
})
