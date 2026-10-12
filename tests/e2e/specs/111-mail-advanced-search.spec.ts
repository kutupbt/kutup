import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Advanced search (docs/plans/mail-parity.md, P6), as Proton's: a keyword,
// the location, a date range, the sender, a recipient, the address, and
// "has attachments", kept in the address bar; Reset goes back.

const PASSWORD = 'Deneme123*MailAdvancedSearchPassword'

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('advanced search: sender, attachments, dates, address; kept in the address bar', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('asalice', PASSWORD)
  const bob = newAccount('asbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const tag = Date.now().toString(36)

  // Bob writes twice: once with a file.
  for (const [subject, file] of [[`Rapor ${tag}`, true], [`Selam ${tag}`, false]] as const) {
    await bobMail.getByRole('button', { name: 'New message' }).first().click()
    const composer = bobMail.getByRole('dialog', { name: 'New message' })
    await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
    await composer.getByRole('combobox', { name: 'To' }).press('Enter')
    await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
    await bobMail.getByRole('textbox', { name: 'Message' }).fill('merhaba')
    const named = bobMail.getByRole('dialog', { name: subject })
    if (file) {
      await bobMail.locator('input[type="file"]:not([accept])').setInputFiles({ name: 'rapor.txt', mimeType: 'text/plain', buffer: Buffer.from(`Rapor ${tag}\n`) })
      await expect(named.getByText('rapor.txt')).toBeVisible({ timeout: 30_000 })
      await expect(named.getByLabel('Uploading')).toHaveCount(0, { timeout: 60_000 })
    }
    await named.getByRole('button', { name: 'Send', exact: true }).click()
    await expect(bobMail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })
  }
  await expect(async () => {
    await mail.reload()
    await expect(mail.getByRole('link', { name: new RegExp(`Selam ${tag}`) })).toBeVisible({ timeout: 2_000 })
    await expect(mail.getByRole('link', { name: new RegExp(`Rapor ${tag}`) })).toBeVisible({ timeout: 2_000 })
  }).toPass({ timeout: 60_000 })

  // Sender and "has attachments", in All mail.
  await mail.getByRole('button', { name: 'Advanced search' }).click()
  let form = mail.getByRole('form', { name: 'Advanced search' })
  await form.getByRole('combobox', { name: 'Location' }).click()
  await mail.getByRole('option', { name: 'All mail' }).click()
  await form.getByRole('textbox', { name: 'Sender' }).fill(bob.username)
  await form.getByRole('checkbox', { name: 'Has attachments' }).click()
  // Address offers Alice's own.
  await form.getByRole('combobox', { name: 'Address' }).click()
  await expect(mail.getByRole('option', { name: `${alice.username}@${domain}` })).toBeVisible()
  await mail.getByRole('option', { name: 'All', exact: true }).click()
  await form.getByRole('button', { name: 'Search' }).click()
  await expect(mail).toHaveURL(new RegExp(`/all\\?from=${bob.username}&filter=attachments$`))
  await expect(mail.getByRole('heading', { name: 'Search results in All mail' })).toBeVisible({ timeout: 30_000 })
  await expect(mail.getByRole('link', { name: new RegExp(`Rapor ${tag}`) })).toBeVisible({ timeout: 30_000 })
  await expect(mail.getByRole('link', { name: new RegExp(`Selam ${tag}`) })).toHaveCount(0)

  // Kept on reload; the form opens with it.
  await mail.reload()
  await expect(mail.getByRole('link', { name: new RegExp(`Rapor ${tag}`) })).toBeVisible({ timeout: 60_000 })
  await expect(mail.getByRole('link', { name: new RegExp(`Selam ${tag}`) })).toHaveCount(0)
  await mail.getByRole('button', { name: 'Advanced search' }).click()
  form = mail.getByRole('form', { name: 'Advanced search' })
  await expect(form.getByRole('textbox', { name: 'Sender' })).toHaveValue(bob.username)
  await expect(form.getByRole('checkbox', { name: 'Has attachments' })).toBeChecked()

  // From tomorrow on: nothing yet.
  const tomorrow = new Date()
  tomorrow.setDate(tomorrow.getDate() + 1)
  const day = `${tomorrow.getFullYear()}-${String(tomorrow.getMonth() + 1).padStart(2, '0')}-${String(tomorrow.getDate()).padStart(2, '0')}`
  await form.getByLabel('Start date').fill(day)
  await form.getByRole('button', { name: 'Search' }).click()
  await expect(mail).toHaveURL(new RegExp(`since=${day}`))
  await expect(mail.getByText('No matches')).toBeVisible({ timeout: 30_000 })

  // Reset: the place without a search.
  await mail.getByRole('button', { name: 'Advanced search' }).click()
  await mail.getByRole('form', { name: 'Advanced search' }).getByRole('button', { name: 'Reset' }).click()
  await expect(mail).toHaveURL(/\/all$/)
  await expect(mail.getByRole('heading', { name: 'All mail' })).toBeVisible({ timeout: 30_000 })
  await expect(mail.getByRole('link', { name: new RegExp(`Selam ${tag}`) })).toBeVisible({ timeout: 30_000 })

  await aliceContext.close()
  await bobContext.close()
})
