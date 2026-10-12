import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Read receipts (docs/plans/mail-parity.md, P3 and P4), as Proton's: the
// composer asks for one, the reader is offered "Send read receipt" (never
// sent on its own), and the sender gets an RFC 8098 report.

const PASSWORD = 'Deneme123*MailReadReceiptPassword'

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('a read receipt: asked for, sent by the reader, received by the sender', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('rralice', PASSWORD)
  const bob = newAccount('rrbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const subject = `Okundu mu ${Date.now().toString(36)}`

  // Bob asks for a read receipt.
  await bobMail.getByRole('button', { name: 'New message' }).first().click()
  const composer = bobMail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await bobMail.getByRole('textbox', { name: 'Message' }).fill('Lütfen okuyunca haber ver.')
  const named = bobMail.getByRole('dialog', { name: subject })
  await named.getByRole('button', { name: 'Read receipt' }).click()
  await expect(named.getByRole('button', { name: 'Read receipt' })).toHaveAttribute('aria-pressed', 'true')
  await named.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(bobMail.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })
  await expect(bobMail.getByRole('button', { name: 'Send', exact: true })).toHaveCount(0, { timeout: 60_000 })

  // Alice is offered one; nothing goes until she sends it.
  await expect(async () => {
    await mail.reload()
    await expect(mail.getByRole('link', { name: new RegExp(subject) })).toBeVisible({ timeout: 2_000 })
  }).toPass({ timeout: 60_000 })
  await mail.getByRole('link', { name: new RegExp(subject) }).click()
  const send = mail.getByRole('button', { name: 'Send read receipt' })
  await expect(send).toBeVisible({ timeout: 60_000 })
  await send.click()
  await expect(mail.getByText('Read receipt sent').first()).toBeVisible({ timeout: 60_000 })
  await expect(send).toHaveCount(0)
  // Noted: after a reload it still says so. The receipt answers Bob's
  // message, so it joins the conversation: Bob's message is folded above it.
  await mail.reload()
  await mail.getByRole('button', { name: new RegExp(`${bob.username}.*End-to-end encrypted`) }).first().click()
  await expect(mail.getByText('Read receipt sent')).toBeVisible({ timeout: 60_000 })
  await expect(send).toHaveCount(0)

  // Bob receives the report, in reply to his message.
  await expect(async () => {
    await bobMail.reload()
    await expect(bobMail.getByRole('link', { name: new RegExp(`Read: ${subject}`) })).toBeVisible({ timeout: 2_000 })
  }).toPass({ timeout: 60_000 })
  await bobMail.getByRole('link', { name: new RegExp(`Read: ${subject}`) }).click()
  await expect(bobMail.frameLocator('iframe[title="Message"]').last().getByText(/was read on/)).toBeVisible({ timeout: 60_000 })

  await aliceContext.close()
  await bobContext.close()
})
