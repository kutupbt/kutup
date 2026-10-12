import { expect, test } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { openWhenArrived } from '../fixtures/mail'

// Images and emoji in the composer (docs/plans/mail-parity.md, P4), as
// Proton's: an image is asked inline or attached (metadata removed) and an
// inline one travels in the text (cid:), not among the files; the emoji
// picker writes into the text.

const PASSWORD = 'Deneme123*MailImagesEmojiPassword'
// A 2×2 red PNG.
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAD91JpzAAAAFklEQVR4nGP8z8DAwMDAxMDAwMDAAAANHQEDasKb6QAAAABJRU5ErkJggg==', 'base64')

test('an inline image and an emoji, received in the text', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const alice = newAccount('imalice', PASSWORD)
  await registerAccount(context, alice)
  const mail = await context.newPage()
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  const subject = `Resimli ${Date.now().toString(36)}`
  await mail.getByRole('button', { name: 'New message' }).first().click()
  const composer = mail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  const named = mail.getByRole('dialog', { name: subject })
  await mail.getByRole('textbox', { name: 'Message' }).fill('Bakın: ')

  // Insert image → Inline, metadata removed by default.
  await mail.locator('input[type="file"][accept="image/*"]').setInputFiles({ name: 'kirmizi.png', mimeType: 'image/png', buffer: PNG })
  const ask = mail.getByRole('dialog', { name: 'Insert image' })
  await expect(ask.getByRole('checkbox', { name: /Remove metadata/ })).toBeChecked()
  await ask.getByRole('button', { name: 'Inline' }).click()
  await expect(mail.getByRole('textbox', { name: 'Message' }).locator('img')).toHaveCount(1)
  // Inline: not among the attached files.
  await expect(named.getByRole('list', { name: 'Attachments' })).toHaveCount(0)
  await expect(named.getByLabel('Uploading')).toHaveCount(0, { timeout: 60_000 })

  // An emoji from the picker.
  await named.getByRole('button', { name: 'Insert emoji' }).click()
  const picker = mail.locator('em-emoji-picker')
  await picker.locator('input[type="search"]').fill('rocket')
  await picker.locator('button[aria-label="🚀"]').first().click()
  await expect(mail.getByRole('textbox', { name: 'Message' })).toContainText('🚀')

  await named.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(mail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })
  await openWhenArrived(mail, new RegExp(subject))
  const body = mail.frameLocator('iframe[title="Message"]').last()
  await expect(body.getByText(/Bakın/)).toBeVisible({ timeout: 60_000 })
  await expect(body.getByText(/🚀/)).toBeVisible()
  // The image shows from its own part, not as a file.
  const image = body.locator('img')
  await expect(image).toHaveCount(1)
  await expect.poll(() => image.evaluate((img: HTMLImageElement) => img.naturalWidth)).toBe(2)
  await expect(mail.getByRole('region', { name: /attachments?$/ })).toHaveCount(0)
  await context.close()
})
