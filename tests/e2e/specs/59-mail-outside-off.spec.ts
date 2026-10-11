import { expect, test, type Page } from '@playwright/test'
import { appUrl, newAccount, registerAccount, signInAsAdmin } from '../fixtures/apps'

// Outside sending off, set by an administrator under Administration → Mail
// sending (MAIL_OUTSIDE_SENDING only gives the first value,
// docs/self-hosting.md): it applies at once, without a restart; Mail offers
// no outside sending and says why; a pause an administrator sets is not
// shown, since nobody can send outside, but Administration → Mail sending
// still lists it, so resuming works once sending is on. The change is in
// the activity log.

const PASSWORD = 'Deneme123*OutsideOffPassword'

async function setPolicy(admin: Page, label: 'Nobody' | 'Everyone') {
  await admin.goto(appUrl('account', '/admin/mail'))
  const policy = admin.getByRole('combobox', { name: 'Who may send to outside addresses' })
  await expect(policy).not.toHaveText('Loading…', { timeout: 30_000 })
  if ((await policy.textContent())?.trim() === label) return
  await policy.click()
  await admin.getByRole('option', { name: label }).click()
  await expect(admin.getByText('Outside sending updated.').first()).toBeVisible({ timeout: 30_000 })
  await expect(policy).toHaveText(label)
}

test('with outside sending off, Mail offers Kutup addresses only and hides the pause', async ({ browser }) => {
  test.slow()
  const adminContext = await browser.newContext()
  await signInAsAdmin(adminContext)
  const admin = await adminContext.newPage()
  try {
    await setPolicy(admin, 'Nobody')

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
    await ownerContext.close()

    // The change is in the activity log.
    await admin.goto(appUrl('account', '/admin/activity'))
    await expect(admin.getByText(/changed who may send to outside addresses from .* to Nobody/).first()).toBeVisible({ timeout: 30_000 })
  } finally {
    // The rest of the suite sends outside.
    await setPolicy(admin, 'Everyone')
    await adminContext.close()
  }
})
