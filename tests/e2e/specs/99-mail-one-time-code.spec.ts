import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, appOrigin, newAccount, registerAccount } from '../fixtures/apps'

// One-time codes (docs/plans/mail-parity.md, P3), as Proton's: a recent
// sign-in mail shows its code in the list and in the opened message;
// copying it puts it on the clipboard and moves the mail to Trash.

const PASSWORD = 'Deneme123*MailOneTimeCodePassword'

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('a one-time code: in the list, copied from the message, the mail to Trash', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('otalice', PASSWORD)
  const bob = newAccount('otbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await aliceContext.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: appOrigin('mail') })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const subject = 'Kutup giriş kodu: 482913'

  await bobMail.getByRole('button', { name: 'New message' }).first().click()
  const composer = bobMail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await bobMail.getByRole('textbox', { name: 'Message' }).fill('Merhaba,\nKodunuz: 482913\nBu kodu kimseyle paylaşmayın.')
  await bobMail.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
  await expect(bobMail.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })

  // The list shows the code beside the row.
  const copy = "Copy '482913' to clipboard and move to Trash"
  await expect(async () => {
    await mail.reload()
    await expect(mail.getByRole('button', { name: copy })).toBeVisible({ timeout: 2_000 })
  }).toPass({ timeout: 60_000 })

  // Opened: the code with Copy; copying fills the clipboard and trashes the mail.
  await mail.getByRole('link', { name: new RegExp('Kutup giriş kodu') }).click()
  const opened = mail.getByRole('main').getByText('One-time code:')
  await expect(opened).toBeVisible({ timeout: 60_000 })
  await mail.getByText('One-time code:').locator('..').getByRole('button', { name: copy }).click()
  await expect(mail.getByText("Copied '482913' to clipboard")).toBeVisible()
  expect(await mail.evaluate(() => navigator.clipboard.readText())).toBe('482913')
  await expect(mail.getByText('Moved to Trash.')).toBeVisible({ timeout: 30_000 })
  await expect(mail.getByRole('link', { name: new RegExp('Kutup giriş kodu') })).toHaveCount(0, { timeout: 30_000 })
  await mail.getByRole('link', { name: /^Trash( \d+)?$/ }).click()
  await expect(mail.getByRole('link', { name: new RegExp('Kutup giriş kodu') })).toBeVisible({ timeout: 30_000 })
  // Not in Trash: the code is not offered there.
  await expect(mail.getByRole('button', { name: copy })).toHaveCount(0)

  await aliceContext.close()
  await bobContext.close()
})
