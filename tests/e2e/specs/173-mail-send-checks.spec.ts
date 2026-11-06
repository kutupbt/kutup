import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Proton's questions before a send (docs/plans/mail-parity.md, Writing): a
// no-reply recipient, a missing subject, and an attachment the text
// mentions but the message lacks each ask "Send anyway?"; Cancel keeps the
// composer open and sends nothing.

const PASSWORD = 'Deneme123*MailSendChecksPassword'

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('no subject, a mentioned attachment and a no-reply address ask before sending', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('sendchk', PASSWORD)
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(context, alice)
  const mail = await openMail(context)
  const question = mail.getByTestId('compose-send-check')

  // To herself, no subject, "ekte" and no file: the subject first, then the attachment.
  await mail.getByRole('button', { name: 'New message' }).first().click()
  const composer = mail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await mail.getByRole('textbox', { name: 'Message' }).fill('Raporu ekte bulabilirsiniz.')
  await composer.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(question.getByRole('heading', { name: 'Subject missing' })).toBeVisible()
  await question.getByRole('button', { name: 'Send anyway' }).click()
  await expect(question.getByRole('heading', { name: 'No attachment found' })).toBeVisible()
  await expect(question).toContainText('“ekte”')
  // Cancel: nothing goes, the composer stays.
  await question.getByRole('button', { name: 'Cancel' }).click()
  await expect(question).toHaveCount(0)
  await expect(composer).toBeVisible()
  await expect(mail.getByText('Message sent')).toHaveCount(0)

  // With a subject, only the attachment asks; Send anyway sends.
  await composer.getByRole('textbox', { name: 'Subject' }).fill('Rapor')
  const named = mail.getByRole('dialog', { name: 'Rapor' })
  await named.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(question.getByRole('heading', { name: 'No attachment found' })).toBeVisible()
  await question.getByRole('button', { name: 'Send anyway' }).click()
  await expect(mail.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })

  // A no-reply address asks first, with Don't show again.
  await mail.getByRole('button', { name: 'New message' }).first().click()
  const second = mail.getByRole('dialog', { name: 'New message' })
  await second.getByRole('combobox', { name: 'To' }).fill(`no-reply@${domain}`)
  await second.getByRole('combobox', { name: 'To' }).press('Enter')
  await second.getByRole('textbox', { name: 'Subject' }).fill('Merhaba')
  await mail.getByRole('dialog', { name: 'Merhaba' }).getByRole('button', { name: 'Send', exact: true }).click()
  await expect(question.getByRole('heading', { name: 'No-reply address detected' })).toBeVisible()
  await expect(question).toContainText(`no-reply@${domain}`)
  await expect(question.getByRole('checkbox', { name: "Don't show again" })).toBeVisible()
  await question.getByRole('button', { name: 'Cancel' }).click()
  await mail.getByRole('dialog', { name: 'Merhaba' }).getByRole('button', { name: 'Discard draft' }).click()

  await context.close()
})
