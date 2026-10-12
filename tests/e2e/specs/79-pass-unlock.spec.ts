import { expect, test } from '@playwright/test'
import { newAccount, registerAccount } from '../fixtures/apps'
import { createVault, openPass } from '../fixtures/pass'

const PASSWORD = 'Deneme123*PassUnlockAccount'
const VAULT_PASSWORD = 'kasa-79-parola'

test('pass: a vault not kept with the sign-in asks for its key, refuses a wrong one, and can be kept and forgotten', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('pass79', PASSWORD))
  const page = await context.newPage()
  await openPass(page)
  await createVault(page, 'Gizli', VAULT_PASSWORD, false)

  // Not kept: after a reload the vault asks for its key.
  await page.reload()
  const unlock = page.getByRole('heading', { name: 'Unlock Gizli' })
  await expect(unlock).toBeVisible({ timeout: 60_000 })
  await page.getByLabel('Vault password', { exact: true }).fill('yanlış')
  await page.getByRole('checkbox', { name: 'Unlock with my Kutup sign-in' }).click()
  await page.getByRole('button', { name: 'Unlock', exact: true }).click()
  await expect(page.getByText('That password or key file does not open this vault.')).toBeVisible({ timeout: 30_000 })

  // The right key, not kept: asked again next time.
  await page.getByLabel('Vault password', { exact: true }).fill(VAULT_PASSWORD)
  await page.getByRole('button', { name: 'Unlock', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Gizli', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await page.reload()
  await expect(unlock).toBeVisible({ timeout: 60_000 })

  // Kept this time: opens with the sign-in.
  await page.getByLabel('Vault password', { exact: true }).fill(VAULT_PASSWORD)
  await page.getByRole('button', { name: 'Unlock', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Gizli', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Gizli', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })

  // Locked, it opens again with the sign-in.
  await page.getByRole('button', { name: 'Vault actions' }).click()
  await page.getByRole('menuitem', { name: 'Lock vault' }).click()
  await expect(page.getByRole('heading', { name: 'Vaults', exact: true })).toBeVisible()
  await page.getByRole('link', { name: /Gizli/ }).last().click()
  await expect(page.getByRole('heading', { name: 'Gizli', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })

  // Forgotten: asked again.
  await page.getByRole('button', { name: 'Vault actions' }).click()
  await page.getByRole('menuitem', { name: 'Stop unlocking with my sign-in' }).click()
  await expect(page.getByText('no longer kept in your account')).toBeVisible()
  await page.reload()
  await expect(unlock).toBeVisible({ timeout: 60_000 })
  await context.close()
})
