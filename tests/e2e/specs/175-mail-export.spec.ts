import { readFile } from 'node:fs/promises'
import { expect, test } from '../fixtures/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { openWhenArrived } from '../fixtures/mail'

// Export mail (docs/plans/mail-parity.md, Data): Settings → General →
// Export downloads a place's messages, opened in the browser, as .eml files
// in a zip (Proton's Export).

const PASSWORD = 'Deneme123*MailExportPassword'

test('the Inbox exported as a zip of .eml files', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('mailexport', PASSWORD)
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 }, acceptDownloads: true })
  await registerAccount(context, alice)
  const mail = await context.newPage()
  await mail.goto(appUrl('mail'))
  await expect(mail.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })

  const subject = `Dışa aktarma ${Date.now()}`
  await mail.getByRole('button', { name: 'New message' }).first().click()
  const composer = mail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await mail.getByRole('textbox', { name: 'Message' }).fill('Bu ileti zip içinde olmalı.')
  await mail.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
  await openWhenArrived(mail, new RegExp(subject))

  await mail.goto(appUrl('mail', '/settings/general'))
  const section = mail.getByRole('region', { name: 'Export mail' })
  await section.getByRole('combobox', { name: 'What to export' }).click()
  await mail.getByRole('option', { name: 'Inbox' }).click()
  const download = mail.waitForEvent('download')
  await section.getByRole('button', { name: 'Export' }).click()
  const file = await download
  expect(file.suggestedFilename()).toMatch(/^Kutup Mail - Inbox - \d{4}-\d{2}-\d{2}\.zip$/)
  // Stored, not compressed: the message's own text is in the zip as written.
  const zip = await readFile((await file.path())!)
  expect(zip.subarray(0, 2).toString('latin1')).toBe('PK')
  expect(zip.includes(Buffer.from('.eml'))).toBe(true)
  expect(zip.includes(Buffer.from(`Subject:`))).toBe(true)
  await expect(mail.getByText('Your mail is downloaded.')).toBeVisible()

  await context.close()
})
