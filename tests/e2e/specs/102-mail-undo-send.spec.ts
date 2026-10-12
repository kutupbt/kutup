import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Undo send (docs/plans/mail-parity.md, P4), as Proton's DelaySendSeconds:
// "Message sent" with Undo while the server holds the send; Undo opens the
// draft again and nothing arrives; left alone, it arrives after the delay.

const PASSWORD = 'Deneme123*MailUndoSendPassword'

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('undo send: taken back into the composer, then sent after the delay', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('usalice', PASSWORD)
  const bob = newAccount('usbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const subject = `Geri al ${Date.now().toString(36)}`

  // Undo send: 10 seconds, Proton's default (the test stack starts with it
  // off, MAIL_DEFAULT_DELAY_SEND_SECONDS=0, so other specs' mail goes at once).
  await bobMail.goto(appUrl('mail', '/settings/general'))
  const undo = bobMail.getByRole('combobox', { name: 'Undo send' })
  await expect(undo).toHaveText('Off', { timeout: 60_000 })
  await undo.click()
  await bobMail.getByRole('option', { name: '10 seconds' }).click()
  await expect(bobMail.getByText('Preference saved.')).toBeVisible({ timeout: 30_000 })
  await bobMail.goto(appUrl('mail'))
  await expect(bobMail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 60_000 })

  await bobMail.getByRole('button', { name: 'New message' }).first().click()
  const composer = bobMail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await bobMail.getByRole('textbox', { name: 'Message' }).fill('Bunu geri alacağım.')
  const named = bobMail.getByRole('dialog', { name: subject })
  await expect(named.getByText('Saved')).toBeVisible({ timeout: 30_000 })
  await named.getByRole('button', { name: 'Send', exact: true }).click()

  // Undo: the composer opens again with the message as it was.
  const sent = bobMail.locator('[data-sonner-toast]').filter({ hasText: 'Message sent' })
  await sent.getByRole('button', { name: 'Undo' }).click()
  await expect(bobMail.getByText('Sending undone.')).toBeVisible({ timeout: 30_000 })
  const back = bobMail.getByRole('dialog', { name: subject })
  await expect(back).toBeVisible()
  await expect(bobMail.getByRole('textbox', { name: 'Message' })).toContainText('Bunu geri alacağım.')
  // Nothing arrived, even past the delay.
  await mail.waitForTimeout(12_000)
  await mail.reload()
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 60_000 })
  await expect(mail.getByRole('link', { name: new RegExp(subject) })).toHaveCount(0)

  // Sent again and left alone: it arrives after the delay.
  await back.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(bobMail.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })
  await expect(async () => {
    await mail.reload()
    await expect(mail.getByRole('link', { name: new RegExp(subject) })).toBeVisible({ timeout: 2_000 })
  }).toPass({ timeout: 60_000 })
  // And it left Bob's drafts for Sent.
  await bobMail.getByRole('link', { name: /^Sent( \d+)?$/ }).click()
  await expect(bobMail.getByRole('link', { name: new RegExp(subject) })).toBeVisible({ timeout: 30_000 })
  await bobMail.getByRole('link', { name: /^Drafts( \d+)?$/ }).click()
  await expect(bobMail.getByRole('link', { name: new RegExp(subject) })).toHaveCount(0, { timeout: 30_000 })

  await aliceContext.close()
  await bobContext.close()
})
