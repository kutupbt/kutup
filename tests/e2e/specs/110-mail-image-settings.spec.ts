import { expect, test } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { openWhenArrived } from '../fixtures/mail'

// Image settings (docs/plans/mail-parity.md, P5), as Proton's: "Auto show
// embedded images" off holds a message's own images until loaded; "Remove
// image metadata" is where the insert question starts.

const PASSWORD = 'Deneme123*MailImageSettingsPassword'
// A 2×2 red PNG.
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAD91JpzAAAAFklEQVR4nGP8z8DAwMDAxMDAwMDAAAANHQEDasKb6QAAAABJRU5ErkJggg==', 'base64')

test('embedded images wait when turned off; metadata removal starts as set', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const alice = newAccount('isalice', PASSWORD)
  await registerAccount(context, alice)
  const mail = await context.newPage()
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  await mail.goto(appUrl('mail', '/settings/general'))

  // Both on by default; turned off and kept.
  const embedded = mail.getByRole('checkbox', { name: /Auto show embedded images/ })
  const metadata = mail.getByRole('checkbox', { name: /Remove image metadata/ })
  await expect(embedded).toBeChecked({ timeout: 120_000 })
  await expect(metadata).toBeChecked()
  const saved = () => mail.waitForResponse((r) => r.request().method() === 'PATCH' && new URL(r.url()).pathname === '/api/mail/settings' && r.ok())
  let save = saved()
  await embedded.click()
  await save
  save = saved()
  await metadata.click()
  await save
  await mail.reload()
  await expect(embedded).not.toBeChecked({ timeout: 60_000 })
  await expect(metadata).not.toBeChecked()

  // The insert question starts with metadata kept.
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  const subject = `Gömülü ${Date.now().toString(36)}`
  await mail.getByRole('button', { name: 'New message' }).first().click()
  const composer = mail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await mail.getByRole('textbox', { name: 'Message' }).fill('Bakın: ')
  await mail.locator('input[type="file"][accept="image/*"]').setInputFiles({ name: 'kirmizi.png', mimeType: 'image/png', buffer: PNG })
  const ask = mail.getByRole('dialog', { name: 'Insert image' })
  await expect(ask.getByRole('checkbox', { name: /Remove metadata/ })).not.toBeChecked()
  await ask.getByRole('button', { name: 'Inline' }).click()
  const named = mail.getByRole('dialog', { name: subject })
  await expect(named.getByLabel('Uploading')).toHaveCount(0, { timeout: 60_000 })
  await named.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(mail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })

  // Received: the image waits until loaded.
  await openWhenArrived(mail, new RegExp(subject))
  const body = mail.frameLocator('iframe[title="Message"]').last()
  await expect(body.getByText(/Bakın/)).toBeVisible({ timeout: 60_000 })
  await expect(mail.getByText('This message contains embedded images.')).toBeVisible()
  await expect(body.locator('img[src^="blob:"]')).toHaveCount(0)
  await mail.getByRole('button', { name: 'Load embedded images' }).click()
  const image = body.locator('img[src^="blob:"]')
  await expect(image).toHaveCount(1)
  await expect.poll(() => image.evaluate((img: HTMLImageElement) => img.naturalWidth)).toBe(2)
  await expect(mail.getByText('This message contains embedded images.')).toHaveCount(0)
  await context.close()
})
