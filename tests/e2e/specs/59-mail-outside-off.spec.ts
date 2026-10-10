import { expect, test } from '@playwright/test'
import { appUrl, newAccount, registerAccount, signInAsAdmin } from '../fixtures/apps'

// Outside sending off, the default (MAIL_OUTSIDE_SENDING, docs/self-hosting.md):
// Mail offers no outside sending and says why; a pause an administrator sets
// is not shown, since nobody can send outside, but Administration → Mail
// sending still lists it, so resuming works once sending is on.

const PASSWORD = 'Deneme123*OutsideOffPassword'

test.skip(process.env.E2E_MAIL_OUTSIDE_SENDING !== 'off', 'needs a stack with MAIL_OUTSIDE_SENDING=off')

test('with outside sending off, Mail offers Kutup addresses only and hides the pause', async ({ browser }) => {
  test.slow()
  const owner = newAccount('mailoff', PASSWORD)
  const ownerContext = await browser.newContext()
  await registerAccount(ownerContext, owner)
  const mail = await ownerContext.newPage()
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })

  // An outside recipient: the composer says so and does not send.
  await mail.getByRole('button', { name: 'New message' }).click()
  const composer = mail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox').first().fill('someone@example.invalid')
  await composer.getByRole('combobox').first().press('Enter')
  const notice = "This server doesn't send mail to addresses outside Kutup yet. Mail to Kutup addresses goes as usual."
  await expect(mail.getByRole('status').filter({ hasText: notice })).toBeVisible({ timeout: 30_000 })
  await composer.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(mail.getByText("Mail to addresses outside Kutup isn't available on this server yet.", { exact: false })).toBeVisible()
  await composer.getByRole('button', { name: 'Discard draft' }).click()

  // An administrator pauses the account: listed as paused, not shown to its owner.
  const adminContext = await browser.newContext()
  await signInAsAdmin(adminContext)
  const admin = await adminContext.newPage()
  await admin.goto(appUrl('account', '/admin/users'))
  await admin.getByRole('link', { name: new RegExp(owner.username) }).first().click()
  const card = admin.getByRole('region', { name: 'Mail sending' }).or(admin.locator('section', { hasText: 'Mail sending' })).first()
  await card.getByRole('button', { name: 'Pause' }).click()
  await expect(card.getByText('Paused by an administrator')).toBeVisible({ timeout: 30_000 })
  await admin.goto(appUrl('account', '/admin/mail'))
  await admin.getByRole('checkbox', { name: 'Only paused and flagged accounts' }).click()
  const row = admin.getByRole('row', { name: new RegExp(owner.username) })
  await expect(row.getByText('Paused by an administrator')).toBeVisible({ timeout: 30_000 })

  await mail.reload()
  await mail.getByRole('button', { name: 'New message' }).click()
  await expect(mail.getByRole('dialog', { name: 'New message' })).toBeVisible()
  await expect(mail.getByRole('status').filter({ hasText: 'paused' })).toHaveCount(0)

  // Resuming still works.
  await row.getByRole('button', { name: 'Resume' }).click()
  await expect(row).toHaveCount(0, { timeout: 30_000 })
  await adminContext.close()
  await ownerContext.close()
})
