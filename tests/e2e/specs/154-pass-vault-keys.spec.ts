import { expect, test } from '@playwright/test'
import { newAccount, registerAccount } from '../fixtures/apps'
import { addEntry, createVault, expectSaved, openPass } from '../fixtures/pass'

const PASSWORD = 'Deneme123*PassVaultKeys'

test('pass: a new vault gets a random key kept in the account, shown for KeePass apps after the password, and opens with it', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await registerAccount(context, newAccount('pass154', PASSWORD))
  const page = await context.newPage()
  await openPass(page)

  // The default: no password to choose; it opens with the sign-in.
  await createVault(page, 'Anahtarlı', null)
  await addEntry(page, { title: 'Banka', password: 'p0' })
  await expectSaved(page)
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Anahtarlı', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })

  // Shown only after the account password; copied as it is.
  await page.getByRole('button', { name: 'Vault actions' }).click()
  await page.getByRole('menuitem', { name: 'Show vault key…' }).click()
  const dialog = page.getByRole('dialog', { name: 'Key of Anahtarlı' })
  await expect(dialog.getByLabel('Vault key')).toHaveCount(0)
  await dialog.getByLabel('Your Kutup password').fill('not my password')
  await dialog.getByRole('button', { name: 'Show key' }).click()
  await expect(dialog.getByText('That is not your Kutup password.')).toBeVisible({ timeout: 30_000 })
  await dialog.getByLabel('Your Kutup password').fill(PASSWORD)
  await dialog.getByRole('button', { name: 'Show key' }).click()
  await expect(dialog.getByLabel('Vault key')).toHaveText('•••••-•••••-•••••-•••••-•••••', { timeout: 30_000 })
  await dialog.getByRole('button', { name: 'Show password' }).click()
  const key = (await dialog.getByLabel('Vault key').textContent()) ?? ''
  expect(key).toMatch(/^[0-9a-hjkmnp-tv-z]{5}(-[0-9a-hjkmnp-tv-z]{5}){4}$/)
  await dialog.getByRole('button', { name: 'Copy vault key' }).click()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(key)
  await dialog.getByRole('button', { name: 'Close' }).last().click()

  // Forgetting a generated key warns first; then the key opens the vault
  // as a KeePass app would open it: typed as its password.
  await page.getByRole('button', { name: 'Vault actions' }).click()
  await page.getByRole('menuitem', { name: 'Stop unlocking with my sign-in' }).click()
  const warning = page.getByRole('alertdialog', { name: "Forget this vault's key?" })
  await expect(warning.getByText('Show the vault key and save it first', { exact: false })).toBeVisible()
  await warning.getByRole('button', { name: 'Stop unlocking with my sign-in' }).click()
  await expect(page.getByText("The vault's key is no longer kept in your account")).toBeVisible({ timeout: 30_000 })
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Unlock Anahtarlı' })).toBeVisible({ timeout: 60_000 })
  await page.getByLabel('Vault password', { exact: true }).fill(key)
  await page.getByRole('button', { name: 'Unlock', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Anahtarlı', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await expect(page.getByRole('list', { name: 'Entries' }).getByRole('button', { name: 'Banka' })).toBeVisible()

  // A vault with a password the person chose has no key to show.
  await createVault(page, 'Parolalı', 'kendi-parolam-154')
  await page.getByRole('button', { name: 'Vault actions' }).click()
  await expect(page.getByRole('menuitem', { name: 'Stop unlocking with my sign-in' })).toBeVisible()
  await expect(page.getByRole('menuitem', { name: 'Show vault key…' })).toHaveCount(0)
  await context.close()
})
