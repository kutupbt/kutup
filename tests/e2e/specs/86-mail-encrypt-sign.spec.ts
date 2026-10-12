import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Encrypt and Sign per message (docs/plans/mail-encrypt-sign.md): with
// Encrypt off, a Kutup recipient gets the message readable on the way (the
// composer says so, the chip shows an open lock), stored zero-access, signed
// and verified against the sender's key list; with Sign off, end to end but
// unsigned. With "Sign outside mail" off, mail to an outside address starts
// unsigned.

const PASSWORD = 'Deneme123*MailEncryptSignPassword'
const SHOTS = process.env.MAIL_UX_SHOTS

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

async function compose(page: Page, to: string, subject: string) {
  await page.getByRole('button', { name: 'New message' }).first().click()
  const composer = page.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(to)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await page.getByRole('textbox', { name: 'Message' }).fill(`${subject} gövdesi`)
  return page.getByRole('dialog', { name: subject })
}

test('Encrypt off (readable, signed, verified) and Sign off (end to end, unsigned)', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('encalice', PASSWORD)
  const bob = newAccount('encbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const tag = Date.now().toString(36)
  const to = `${bob.username}@${domain}`

  // Encrypt off: the warning, an open lock on Bob's chip; Sign stays on.
  const readable = `Okunur ${tag}`
  let composer = await compose(mail, to, readable)
  await composer.getByRole('button', { name: 'Encrypt' }).click()
  await expect(composer.getByRole('button', { name: 'Encrypt' })).toHaveAttribute('aria-pressed', 'false')
  await expect(composer.getByText(/Kutup can read this message while delivering it/)).toBeVisible()
  await expect(composer.getByRole('img', { name: 'Not end-to-end encrypted for this message: encrypted when it arrives' })).toBeVisible({ timeout: 30_000 })
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/composer-encrypt-off.png` })
  await composer.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(mail.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })
  // The toast may be the last send's: wait for this composer to close.
  await expect(mail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })

  // Bob: zero-access, signed by a verified sender, body readable.
  // Held for undo send first: Bob's list shows it once it went.
  await expect(async () => {
    await bobMail.reload()
    await expect(bobMail.getByRole('link', { name: new RegExp(readable) })).toBeVisible({ timeout: 2_000 })
  }).toPass({ timeout: 60_000 })
  await bobMail.getByRole('link', { name: new RegExp(readable) }).click()
  await expect(bobMail.frameLocator('iframe[title="Message"]').last().getByText(`${readable} gövdesi`)).toBeVisible({ timeout: 60_000 })
  await expect(bobMail.getByRole('article').getByRole('img', { name: 'Signed by a verified sender; not end-to-end encrypted' })).toBeVisible({ timeout: 30_000 })
  if (SHOTS) await bobMail.screenshot({ path: `${SHOTS}/read-signed-not-encrypted.png` })

  // Sign off, Encrypt on: end to end, not verified as from Alice.
  const unsigned = `İmzasız ${tag}`
  composer = await compose(mail, to, unsigned)
  await composer.getByRole('button', { name: 'Sign' }).click()
  await expect(composer.getByRole('button', { name: 'Sign' })).toHaveAttribute('aria-pressed', 'false')
  await composer.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(mail.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })
  // The toast may be the last send's: wait for this composer to close.
  await expect(mail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })
  await bobMail.goto(appUrl('mail', '/inbox'))
  await expect(async () => {
    await bobMail.reload()
    await expect(bobMail.getByRole('link', { name: new RegExp(unsigned) })).toBeVisible({ timeout: 2_000 })
  }).toPass({ timeout: 60_000 })
  await bobMail.getByRole('link', { name: new RegExp(unsigned) }).click()
  await expect(bobMail.frameLocator('iframe[title="Message"]').last().getByText(`${unsigned} gövdesi`)).toBeVisible({ timeout: 60_000 })
  await expect(bobMail.getByRole('article').getByRole('img', { name: 'End-to-end encrypted' })).toBeVisible()

  // "Sign outside mail" off: an outside recipient starts with Sign off.
  await mail.goto(appUrl('mail', '/settings/general'))
  const signOutside = mail.getByRole('checkbox', { name: /Sign outside mail/ })
  await expect(signOutside).toBeChecked()
  await signOutside.click()
  await expect(mail.getByText('Preference saved.').first()).toBeVisible()
  await expect(signOutside).not.toBeChecked()
  composer = await compose(mail, `someone-${tag}@example.org`, `Dışarı ${tag}`)
  await expect(composer.getByRole('button', { name: 'Sign' })).toHaveAttribute('aria-pressed', 'false')

  await aliceContext.close()
  await bobContext.close()
})
