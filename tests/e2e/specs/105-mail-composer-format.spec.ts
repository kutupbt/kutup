import { expect, test, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { openWhenArrived } from '../fixtures/mail'

// Composer defaults (docs/plans/mail-parity.md, P4), as Proton's: the
// default font and size reach the sent HTML; Composer mode "Plain text"
// writes in a text box and sends text/plain; "More options" switches a
// message between the two, keeping its text.

const PASSWORD = 'Deneme123*MailComposerFormatPassword'

async function choose(mail: Page, label: string, option: string) {
  await mail.getByRole('combobox', { name: label, exact: true }).click()
  await mail.getByRole('option', { name: option }).click()
  await expect(mail.getByText('Preference saved.').last()).toBeVisible({ timeout: 30_000 })
}

test('composer defaults: font and size sent, plain text mode, switching keeps the text', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const alice = newAccount('cfalice', PASSWORD)
  await registerAccount(context, alice)
  const mail = await context.newPage()
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  const tag = Date.now().toString(36)
  const write = async (subject: string, text: string) => {
    await mail.getByRole('button', { name: 'New message' }).first().click()
    const composer = mail.getByRole('dialog', { name: 'New message' })
    await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
    await composer.getByRole('combobox', { name: 'To' }).press('Enter')
    await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
    await mail.getByRole('textbox', { name: 'Message' }).fill(text)
    return mail.getByRole('dialog', { name: subject })
  }

  // Georgia, 18 px: in the HTML that arrives.
  await mail.goto(appUrl('mail', '/settings/appearance'))
  await choose(mail, 'Default font', 'Georgia')
  await choose(mail, 'Default font size', '18 px')
  await mail.goto(appUrl('mail'))
  const styled = `Biçimli ${tag}`
  let composer = await write(styled, 'Georgia ile yazıldı.')
  await composer.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(mail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })
  await openWhenArrived(mail, new RegExp(styled))
  const body = mail.frameLocator('iframe[title="Message"]').last()
  await expect(body.locator('div[style*="Georgia"][style*="18px"]').getByText('Georgia ile yazıldı.')).toBeVisible({ timeout: 60_000 })

  // Plain text by default: a text box, sent as plain text.
  await mail.goto(appUrl('mail', '/settings/appearance'))
  await choose(mail, 'Composer mode', 'Plain text')
  await mail.goto(appUrl('mail'))
  const plain = `Düz ${tag}`
  composer = await write(plain, 'Birinci satır\nİkinci satır')
  await expect(mail.getByRole('textbox', { name: 'Message' })).toHaveJSProperty('tagName', 'TEXTAREA')
  await composer.getByRole('button', { name: 'More options' }).click()
  await expect(mail.getByRole('menuitemcheckbox', { name: 'Plain text' })).toHaveAttribute('aria-checked', 'true')
  // Back to Normal for a moment: the text stays, now in the editor.
  await mail.getByRole('menuitemcheckbox', { name: 'Plain text' }).click()
  await expect(mail.getByRole('textbox', { name: 'Message' })).toContainText('İkinci satır')
  await composer.getByRole('button', { name: 'More options' }).click()
  await mail.getByRole('menuitemcheckbox', { name: 'Plain text' }).click()
  await expect(mail.getByRole('textbox', { name: 'Message' })).toHaveValue('Birinci satır\nİkinci satır')
  await composer.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(mail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })
  await openWhenArrived(mail, new RegExp(plain))
  await expect(body.getByText('İkinci satır')).toBeVisible({ timeout: 60_000 })
  // Plain text: no styled wrapper.
  await expect(body.locator('div[style*="Georgia"]')).toHaveCount(0)
  await context.close()
})
