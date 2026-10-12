import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// A message's files (docs/plans/mail-parity.md, P3), as Proton's: how many
// are attached, a preview for text and images with previous and next, and
// Download all as one zip.

const PASSWORD = 'Deneme123*MailAttachmentsPassword'
// A 1×1 red PNG.
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==', 'base64')

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('files attached: preview, previous and next, Download all', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('atalice', PASSWORD)
  const bob = newAccount('atbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 }, acceptDownloads: true })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const tag = Date.now().toString(36)
  const subject = `Ekler ${tag}`

  await bobMail.getByRole('button', { name: 'New message' }).first().click()
  const composer = bobMail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await bobMail.getByRole('textbox', { name: 'Message' }).fill('iki dosya')
  const named = bobMail.getByRole('dialog', { name: subject })
  await bobMail.locator('input[type="file"]').setInputFiles([
    { name: 'notlar.txt', mimeType: 'text/plain', buffer: Buffer.from(`Notlar ${tag}\n`) },
    { name: 'nokta.png', mimeType: 'image/png', buffer: PNG },
  ])
  await expect(named.getByText('nokta.png')).toBeVisible({ timeout: 30_000 })
  await expect(named.getByLabel('Uploading')).toHaveCount(0, { timeout: 60_000 })
  await named.getByRole('button', { name: 'Send', exact: true }).click()
  await expect(bobMail.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })
  // The toast may be the last send's: wait for this composer to close.
  await expect(bobMail.getByRole('button', { name: 'Send', exact: true })).toHaveCount(0, { timeout: 60_000 })

  await expect(async () => {
    await mail.reload()
    await expect(mail.getByRole('link', { name: new RegExp(subject) })).toBeVisible({ timeout: 2_000 })
  }).toPass({ timeout: 60_000 })
  await mail.getByRole('link', { name: new RegExp(subject) }).click()
  const files = mail.getByRole('region', { name: '2 attachments' })
  await expect(files.getByText('2 files attached')).toBeVisible({ timeout: 60_000 })

  // The text previews in place; next shows the image.
  await files.getByRole('button', { name: /notlar\.txt/ }).first().click()
  const preview = mail.getByRole('dialog', { name: 'notlar.txt' })
  await expect(preview.getByLabel('notlar.txt')).toHaveText(`Notlar ${tag}\n`)
  await expect(preview.getByText(/1 of 2/)).toBeVisible()
  await preview.getByRole('button', { name: 'Next file' }).click()
  const image = mail.getByRole('dialog', { name: 'nokta.png' }).getByRole('img', { name: 'nokta.png' })
  await expect(image).toBeVisible()
  await expect.poll(() => image.evaluate((img: HTMLImageElement) => img.naturalWidth)).toBe(1)
  const one = mail.waitForEvent('download')
  await mail.getByRole('dialog', { name: 'nokta.png' }).getByRole('button', { name: 'Download', exact: true }).click()
  expect((await one).suggestedFilename()).toBe('nokta.png')
  // Escape closes the preview only; the message stays open.
  await mail.keyboard.press('Escape')
  await expect(mail.getByRole('dialog')).toHaveCount(0)
  await expect(files).toBeVisible()

  // Download all: one zip named for the subject.
  const all = mail.waitForEvent('download')
  await files.getByRole('button', { name: 'Download all attachments' }).click()
  const zip = await all
  expect(zip.suggestedFilename()).toBe(`Attachments-${subject}.zip`)
  const bytes = await (await zip.createReadStream()).toArray()
  const data = Buffer.concat(bytes as Buffer[])
  // A zip's local file headers name both files.
  expect(data.subarray(0, 4).toString('hex')).toBe('504b0304')
  expect(data.includes(Buffer.from('notlar.txt'))).toBe(true)
  expect(data.includes(Buffer.from('nokta.png'))).toBe(true)

  await aliceContext.close()
  await bobContext.close()
})
