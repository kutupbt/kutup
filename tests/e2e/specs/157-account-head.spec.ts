import { execSync } from 'node:child_process'
import { expect, test } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { createVault, openPass } from '../fixtures/pass'

// Rollback protection across devices (docs/plans/rollback-protection.md):
// listed writes carry the account head, Account → Security shows the state,
// and an app shown an older history than it saw stops its listed writes
// until the person continues with the server's data.

const PASSWORD = 'Deneme123*AccountHeadSpec'

test('a kept vault key starts the account head, and Account → Security shows it', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('head157', PASSWORD))
  const page = await context.newPage()

  // Nothing changed yet.
  await page.goto(appUrl('account', '/settings/security'))
  await expect(page.getByText('No changes yet.')).toBeVisible({ timeout: 30_000 })

  // A vault whose key Kutup Pass keeps: the chain starts (#1), and the keep
  // follows it (#2).
  await openPass(page)
  await createVault(page, 'Kişisel', null)

  await page.goto(appUrl('account', '/settings/security'))
  await expect(page.getByText('#2', { exact: true })).toBeVisible({ timeout: 30_000 })
  // Pass wrote it: another app, as far as Account is concerned.
  await expect(page.getByText('Last changed on another device or app')).toBeVisible()
  await page.getByText("This app's history").click()
  await expect(page.getByText('Started following #2')).toBeVisible()

  // Another kept key: #3, and no app shows a warning.
  await openPass(page)
  await createVault(page, 'İş', null)
  await expect(page.getByText('Your data in this app and on the server disagree')).toHaveCount(0)
  await page.goto(appUrl('account', '/settings/security'))
  await expect(page.getByText('#3', { exact: true })).toBeVisible({ timeout: 30_000 })
  await context.close()
})

// The server rolled back: only the test stack's owner can do that to it, so
// this runs where a command is given that runs SQL (on its stdin) against the
// stack's database (E2E_PSQL; tests/e2e/README.md).
test('an app shown an older history stops its listed writes until the person continues', async ({ browser }) => {
  const psql = process.env.E2E_PSQL
  test.skip(!psql, 'E2E_PSQL: a command that runs SQL from its stdin against the test stack database')
  test.slow()
  const account = newAccount('head157b', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, account)
  const page = await context.newPage()
  await openPass(page)
  await createVault(page, 'Kişisel', null)

  // The server goes back to the head before the keep (as a restore from a
  // backup would; an attack looks the same).
  execSync(psql!, {
    input: `DELETE FROM account_heads WHERE sequence > 1 AND user_id = (SELECT id FROM users WHERE username = '${account.username}');\n`,
    stdio: ['pipe', 'inherit', 'inherit'],
  })

  await openPass(page)
  const banner = page.getByRole('alert').filter({ hasText: 'Your data in this app and on the server disagree' })
  await expect(banner).toBeVisible({ timeout: 30_000 })

  // The person decides: asked once more, then the warning goes.
  await banner.getByRole('button', { name: "Continue with the server's data" }).click()
  const confirm = page.getByRole('alertdialog')
  await expect(confirm.getByText('The server shows an older state than this app has already seen.')).toBeVisible()
  await confirm.getByRole('button', { name: "Continue with the server's data" }).click()
  // The dialog closes once it is done (while it is open, the page under it
  // is hidden from the accessibility tree, the banner too).
  await expect(confirm).toBeHidden({ timeout: 30_000 })
  await expect(banner).toHaveCount(0)

  // Reloaded, it stays continued (the choice is remembered, sealed, here).
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Vaults', exact: true })).toBeVisible({ timeout: 60_000 })
  await expect(banner).toHaveCount(0)
  await context.close()
})
