import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Identity (docs/plans/mail-parity.md, P2), as Proton's: a display name and a
// signature in Mail → Settings; new messages start with the signature,
// recipients see the name.

const PASSWORD = 'Deneme123*MailIdentityPassword'
const SHOTS = process.env.MAIL_UX_SHOTS

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('display name and signature: set in Settings, used when writing', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('idalice', PASSWORD)
  const bob = newAccount('idbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const tag = Date.now().toString(36)

  await mail.goto(appUrl('mail', '/settings/identity'))
  await expect(mail.getByRole('heading', { name: 'Identity' })).toBeVisible()
  await mail.getByLabel('Display name').fill('Alice Yılmaz')
  const editor = mail.getByLabel('Signature', { exact: true })
  await editor.click()
  await mail.keyboard.type(`Saygılarımla, Alice ${tag}`)
  await mail.getByRole('button', { name: 'Save' }).click()
  await expect(mail.getByText('Preference saved.')).toBeVisible({ timeout: 30_000 })
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/identity-settings.png` })

  // A new message starts with the signature, below two empty lines.
  await mail.goto(appUrl('mail', '/inbox'))
  await mail.getByRole('button', { name: 'New message' }).first().click()
  const composer = mail.getByRole('dialog', { name: 'New message' })
  await expect(composer.getByText(`Saygılarımla, Alice ${tag}`)).toBeVisible({ timeout: 30_000 })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${bob.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  const subject = `Kimlik ${tag}`
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await mail.getByRole('textbox', { name: 'Message' }).press('Control+Home')
  await mail.keyboard.type('Merhaba Bob')
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/composer-signature.png` })
  await mail.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
  await expect(mail.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })
  // The toast may be the last send's: wait for this composer to close.
  await expect(mail.getByRole('button', { name: 'Send', exact: true })).toHaveCount(0, { timeout: 60_000 })

  // Bob sees the name and the signature.
  await expect(async () => {
    await bobMail.reload()
    await expect(bobMail.getByRole('link', { name: new RegExp(subject) })).toBeVisible({ timeout: 2_000 })
  }).toPass({ timeout: 60_000 })
  await bobMail.getByRole('link', { name: new RegExp(subject) }).click()
  await expect(bobMail.getByRole('article').getByText('Alice Yılmaz').first()).toBeVisible({ timeout: 60_000 })
  const body = bobMail.frameLocator('iframe[title="Message"]').last()
  await expect(body.getByText('Merhaba Bob')).toBeVisible({ timeout: 60_000 })
  await expect(body.getByText(`Saygılarımla, Alice ${tag}`)).toBeVisible()

  await aliceContext.close()
  await bobContext.close()
})
