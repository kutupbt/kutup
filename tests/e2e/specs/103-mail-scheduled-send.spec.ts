import { expect, test } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Scheduled send (docs/plans/mail-parity.md, P4), as Proton's: Send's menu
// schedules for tomorrow morning; the message waits in Scheduled with its
// time; opened, it says when it goes, and Edit takes it back to Drafts and
// into the composer. (That it goes at its time is the mail gate's.)

const PASSWORD = 'Deneme123*MailScheduledSendPassword'

test('scheduled send: Scheduled, its time, and Edit back to the composer', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const alice = newAccount('ssalice', PASSWORD)
  await registerAccount(context, alice)
  const mail = await context.newPage()
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  const nav = mail.getByRole('navigation', { name: 'Main navigation' })
  // Nothing scheduled: no Scheduled folder, as Proton's.
  await expect(nav.getByRole('link', { name: /^Scheduled/ })).toHaveCount(0)

  const subject = `Planlı ${Date.now().toString(36)}`
  await mail.getByRole('button', { name: 'New message' }).first().click()
  const composer = mail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await mail.getByRole('textbox', { name: 'Message' }).fill('Yarın sabah gitsin.')
  const named = mail.getByRole('dialog', { name: subject })
  await named.getByRole('button', { name: 'Schedule send' }).click()
  await mail.getByRole('menuitem', { name: /Tomorrow morning/ }).click()
  await expect(mail.getByText(/Message scheduled for/)).toBeVisible({ timeout: 60_000 })
  await expect(named).toHaveCount(0)

  // In Scheduled, with when it goes; not in Drafts.
  await expect(nav.getByRole('link', { name: /^Scheduled/ })).toBeVisible({ timeout: 30_000 })
  await nav.getByRole('link', { name: /^Scheduled/ }).click()
  const row = mail.getByRole('link', { name: new RegExp(subject) })
  await expect(row).toBeVisible({ timeout: 30_000 })
  await expect(mail.getByRole('listitem').filter({ hasText: subject }).getByText(/^Sends /)).toBeVisible()
  await row.click()
  await expect(mail.getByText(/This message will be sent on/)).toBeVisible({ timeout: 60_000 })

  // Edit: back to Drafts, in the composer.
  await mail.getByRole('button', { name: 'Edit', exact: true }).click()
  await expect(mail.getByRole('dialog', { name: subject })).toBeVisible({ timeout: 30_000 })
  await mail.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Close and keep the draft' }).click()
  await nav.getByRole('link', { name: /^Drafts/ }).click()
  await expect(mail.getByRole('link', { name: new RegExp(subject) })).toBeVisible({ timeout: 30_000 })
  await expect(nav.getByRole('link', { name: /^Scheduled/ })).toHaveCount(0, { timeout: 30_000 })
  await context.close()
})
