import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// PGP settings (docs/plans/mail-parity.md, P2), as Proton's External PGP
// settings: "Attach public key" starts each new message with your key
// attached; the Inline scheme sends a signed, unencrypted message as plain
// text with a cleartext signature and a detached .sig beside each file; the
// reader checks both against the sender's key.

const PASSWORD = 'Deneme123*MailPgpSettingsPassword'
const SHOTS = process.env.MAIL_UX_SHOTS

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('attach public key, and an Inline signed message the reader verifies', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('pgpalice', PASSWORD)
  const bob = newAccount('pgpbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const tag = Date.now().toString(36)

  // Settings → General: attach the key, Inline.
  await mail.goto(appUrl('mail', '/settings/general'))
  await expect(mail.getByRole('heading', { name: 'PGP for people outside Kutup' })).toBeVisible()
  await mail.getByRole('checkbox', { name: /Attach public key/ }).click()
  await expect(mail.getByText('Preference saved.').first()).toBeVisible({ timeout: 30_000 })
  await mail.getByRole('combobox', { name: 'Default PGP scheme' }).click()
  await mail.getByRole('option', { name: 'Inline' }).click()
  await expect(mail.getByRole('combobox', { name: 'Default PGP scheme' })).toHaveText('Inline', { timeout: 30_000 })
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/pgp-settings.png` })

  // A new message starts with the key attached; an untouched one closes
  // without a draft, and the key can be removed.
  await mail.goto(appUrl('mail', '/inbox'))
  await mail.getByRole('button', { name: 'New message' }).first().click()
  let composer = mail.getByRole('dialog', { name: 'New message' })
  const keyFile = new RegExp(`publickey - ${alice.username}@${domain.replace(/\./g, '\\.')} - 0x[0-9A-F]{8}\\.asc`)
  await expect(composer.getByText(keyFile)).toBeVisible({ timeout: 30_000 })
  await composer.getByRole('button', { name: /Remove publickey/ }).click()
  await expect(composer.getByText(keyFile)).toHaveCount(0)
  await composer.getByRole('button', { name: 'Close and keep the draft' }).click()
  await expect(composer).toHaveCount(0)

  // Inline, Encrypt off, Sign on, to Bob, with the key attached.
  await mail.getByRole('button', { name: 'New message' }).first().click()
  composer = mail.getByRole('dialog', { name: 'New message' })
  await expect(composer.getByText(keyFile)).toBeVisible({ timeout: 30_000 })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${bob.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  const subject = `Satır içi ${tag}`
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await mail.getByRole('textbox', { name: 'Message' }).fill(`İmzalı düz metin ${tag}`)
  const named = mail.getByRole('dialog', { name: subject })
  await named.getByRole('button', { name: 'Encrypt' }).click()
  await expect(named.getByRole('button', { name: 'Encrypt' })).toHaveAttribute('aria-pressed', 'false')
  await named.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(mail.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })
  // The toast may be the last send's: wait for this composer to close.
  await expect(mail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })

  // Bob: the text, and a verified signature over it and the key file (its
  // .sig is checked, not shown).
  await expect(async () => {
    await bobMail.reload()
    await expect(bobMail.getByRole('link', { name: new RegExp(subject) })).toBeVisible({ timeout: 2_000 })
  }).toPass({ timeout: 60_000 })
  await bobMail.getByRole('link', { name: new RegExp(subject) }).click()
  await expect(bobMail.frameLocator('iframe[title="Message"]').last().getByText(`İmzalı düz metin ${tag}`)).toBeVisible({ timeout: 60_000 })
  await expect(bobMail.getByRole('article').getByRole('img', { name: 'Signed by a verified sender; not end-to-end encrypted' })).toBeVisible({ timeout: 30_000 })
  const files = bobMail.getByRole('region', { name: /attachment/i })
  await expect(files.getByText(keyFile)).toBeVisible()
  await expect(files.getByText(/\.sig$/)).toHaveCount(0)
  if (SHOTS) await bobMail.screenshot({ path: `${SHOTS}/pgp-inline-received.png` })

  await aliceContext.close()
  await bobContext.close()
})
