import { expect, test } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Snooze (docs/plans/mail-parity.md, P4), as Proton's: out of the Inbox
// until its time, in Snoozed with when it comes back; Unsnooze brings it
// back now. (Coming back on its own, unread, is the mail gate's.)

const PASSWORD = 'Deneme123*MailSnoozePassword'

test('snooze: out of the Inbox into Snoozed, and Unsnooze', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const alice = newAccount('snalice', PASSWORD)
  await registerAccount(context, alice)
  const mail = await context.newPage()
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  const subject = `Ertele ${Date.now().toString(36)}`
  await mail.getByRole('button', { name: 'New message' }).first().click()
  const composer = mail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await mail.getByRole('textbox', { name: 'Message' }).fill('Sonra bakarım.')
  await mail.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
  await expect(mail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })

  const list = mail.getByRole('list', { name: 'Messages' })
  const row = () => list.getByRole('listitem').filter({ hasText: subject })
  await expect(async () => {
    await mail.reload()
    await expect(row().first()).toBeVisible({ timeout: 2_000 })
  }).toPass({ timeout: 60_000 })

  // Snoozed till tomorrow: gone from the Inbox, in Snoozed with its time.
  await row().first().getByRole('checkbox').check({ force: true })
  await mail.getByRole('button', { name: 'Snooze' }).click()
  await mail.getByRole('menuitem', { name: /Tomorrow/ }).click()
  await expect(mail.getByText(/snoozed until/)).toBeVisible({ timeout: 30_000 })
  await expect(row()).toHaveCount(0, { timeout: 30_000 })
  const nav = mail.getByRole('navigation', { name: 'Main navigation' })
  await nav.getByRole('link', { name: /^Snoozed/ }).click()
  await expect(row().first()).toBeVisible({ timeout: 30_000 })
  await expect(row().first().getByText(/^Back /)).toBeVisible()

  // Unsnooze: back in the Inbox now.
  await row().first().getByRole('checkbox').check({ force: true })
  await mail.getByRole('button', { name: 'Unsnooze' }).click()
  await expect(mail.getByText(/unsnoozed/)).toBeVisible({ timeout: 30_000 })
  await expect(row()).toHaveCount(0, { timeout: 30_000 })
  await nav.getByRole('link', { name: /^Inbox/ }).click()
  await expect(row().first()).toBeVisible({ timeout: 30_000 })
  await context.close()
})
