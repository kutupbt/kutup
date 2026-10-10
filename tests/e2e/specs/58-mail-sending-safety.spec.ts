import { expect, test } from '@playwright/test'
import { appUrl, newAccount, registerAccount, signInAsAdmin } from '../fixtures/apps'

// Sending safety (docs/plans/mail.md): an administrator pauses an account's
// mail to outside addresses from its user page; its owner sees it in Mail's
// composer; Administration → Mail sending lists it; resuming clears it.

const PASSWORD = 'Deneme123*SendingSafetyPassword'

test('an administrator pauses and resumes an account’s outside mail, and its owner is told', async ({ browser }) => {
  test.slow()
  const owner = newAccount('mailsafety', PASSWORD)
  const ownerContext = await browser.newContext()
  await registerAccount(ownerContext, owner)
  const mail = await ownerContext.newPage()
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })

  const adminContext = await browser.newContext()
  await signInAsAdmin(adminContext)
  const admin = await adminContext.newPage()
  await admin.goto(appUrl('account', '/admin/users'))
  await admin.getByRole('link', { name: new RegExp(owner.username) }).first().click()
  const card = admin.getByRole('region', { name: 'Mail sending' }).or(admin.locator('section', { hasText: 'Mail sending' })).first()
  await expect(card.getByText('Sending normally')).toBeVisible({ timeout: 60_000 })
  await card.getByRole('button', { name: 'Pause' }).click()
  await expect(card.getByText('Paused by an administrator')).toBeVisible({ timeout: 30_000 })

  // The list shows it among the accounts that need attention.
  await admin.goto(appUrl('account', '/admin/mail'))
  await expect(admin.getByRole('heading', { name: 'Mail sending' })).toBeVisible()
  await admin.getByRole('checkbox', { name: 'Only paused and flagged accounts' }).click()
  const row = admin.getByRole('row', { name: new RegExp(owner.username) })
  await expect(row.getByText('Paused by an administrator')).toBeVisible({ timeout: 30_000 })

  // Its owner is told in the composer.
  await mail.reload()
  await mail.getByRole('button', { name: 'New message' }).click()
  await expect(mail.getByRole('status').filter({ hasText: 'Mail to outside addresses is paused for your account' })).toBeVisible({
    timeout: 30_000,
  })
  await mail.getByRole('button', { name: 'Discard draft' }).click()

  // Resumed from the whole list (once resumed it needs no attention).
  await admin.getByRole('checkbox', { name: 'Only paused and flagged accounts' }).click()
  await row.getByRole('button', { name: 'Resume' }).click()
  await expect(row.getByText('Sending normally')).toBeVisible({ timeout: 30_000 })
  await mail.reload()
  await mail.getByRole('button', { name: 'New message' }).click()
  await expect(mail.getByRole('dialog', { name: 'New message' })).toBeVisible()
  await expect(mail.getByRole('status').filter({ hasText: 'paused' })).toHaveCount(0)

  await adminContext.close()
  await ownerContext.close()
})
