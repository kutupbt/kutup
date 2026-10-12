import { expect, test } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { createVault, openPass } from '../fixtures/pass'

const PASSWORD = 'Deneme123*PassUnlockAccount'
const VAULT_PASSWORD = 'kasa-79-parola'

test('pass: its page allows no inline or eval\'d script and cannot be framed', async ({ request }) => {
  const response = await request.get(appUrl('pass'))
  const csp = response.headers()['content-security-policy'] ?? ''
  const script = /script-src ([^;]*)/.exec(csp)?.[1] ?? ''
  expect(script).toContain("'self'")
  expect(script).toContain("'wasm-unsafe-eval'")
  expect(script).not.toContain("'unsafe-inline'")
  expect(script).not.toContain("'unsafe-eval'")
  expect(csp).toContain("frame-ancestors 'none'")
  expect(response.headers()['x-frame-options']).toBe('DENY')
})

test('pass: a vault not kept with the sign-in asks for its key, refuses a wrong one, and can be kept and forgotten', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('pass79', PASSWORD))
  const page = await context.newPage()
  // Nothing on the page may break its policy.
  const violations: string[] = []
  page.on('console', (message) => {
    if (/Content Security Policy/i.test(message.text())) violations.push(message.text())
  })
  await openPass(page)
  const vaultUrl = await createVault(page, 'Gizli', VAULT_PASSWORD, false)

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

  // Locked by hand: it waits for a click, also after a reload.
  await page.getByRole('button', { name: 'Vault actions' }).click()
  await page.getByRole('menuitem', { name: 'Lock vault' }).click()
  await expect(page.getByRole('heading', { name: 'Vaults', exact: true })).toBeVisible()
  await page.goto(vaultUrl)
  await expect(unlock).toBeVisible({ timeout: 60_000 })
  await page.reload()
  await expect(unlock).toBeVisible({ timeout: 60_000 })
  // By default the account password opens it again, checked on the device.
  await page.getByLabel('Your Kutup password').fill('not-my-password')
  await page.getByRole('button', { name: 'Unlock with my password' }).click()
  await expect(page.getByText('That is not your Kutup password.')).toBeVisible({ timeout: 30_000 })
  await page.getByLabel('Your Kutup password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Unlock with my password' }).click()
  await expect(page.getByRole('heading', { name: 'Gizli', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })

  // Idle: locks after the chosen time; set to open with one click.
  await page.goto(appUrl('pass'))
  await page.getByRole('combobox', { name: 'Lock vaults after' }).click()
  await page.getByRole('option', { name: '1 minute', exact: true }).click()
  await page.getByRole('combobox', { name: 'After a lock, open vaults with' }).click()
  await page.getByRole('option', { name: 'One click' }).click()
  const idle = await context.newPage()
  await idle.clock.install()
  await idle.goto(vaultUrl)
  await expect(idle.getByRole('heading', { name: 'Gizli', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await idle.clock.fastForward('01:30')
  await expect(idle.getByRole('heading', { name: 'Unlock Gizli' })).toBeVisible({ timeout: 30_000 })
  await idle.getByRole('button', { name: 'Unlock with my sign-in' }).click()
  await expect(idle.getByRole('heading', { name: 'Gizli', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })

  // Forgotten: asked again.
  await idle.getByRole('button', { name: 'Vault actions' }).click()
  await idle.getByRole('menuitem', { name: 'Stop unlocking with my sign-in' }).click()
  await expect(idle.getByText('no longer kept in your account')).toBeVisible()
  await page.goto(vaultUrl)
  await expect(unlock).toBeVisible({ timeout: 60_000 })
  await expect(page.getByRole('button', { name: 'Unlock with my sign-in' })).toBeHidden()

  // Signed out in the account app: the open vault locks and Pass asks to sign in again.
  await page.getByLabel('Vault password', { exact: true }).fill(VAULT_PASSWORD)
  await page.getByRole('button', { name: 'Unlock', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Gizli', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  const account = await context.newPage()
  await account.goto(appUrl('account'))
  await account.getByRole('button', { name: 'Account menu' }).click()
  await account.getByRole('menuitem', { name: 'Sign out' }).click()
  await expect(account).toHaveURL(/\/login/, { timeout: 30_000 })
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(page).toHaveURL(/account\..*\/(login|authorize)/, { timeout: 60_000 })

  expect(violations).toEqual([])
  await context.close()
})
