import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// The list's filters and sort (docs/plans/mail-parity.md, P3), as Proton's
// FilterList: Unread at hand; Read, Has attachments and the sort options in
// Filter; Reset. They live in the address bar, so opening a message and
// coming back keeps them.

const PASSWORD = 'Deneme123*MailListFiltersPassword'

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('unread, attachments and oldest first; kept across opening a message', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('lfalice', PASSWORD)
  const bob = newAccount('lfbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const tag = Date.now().toString(36)

  const send = async (subject: string, file?: boolean) => {
    await bobMail.getByRole('button', { name: 'New message' }).first().click()
    const composer = bobMail.getByRole('dialog', { name: 'New message' })
    await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
    await composer.getByRole('combobox', { name: 'To' }).press('Enter')
    await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
    await bobMail.getByRole('textbox', { name: 'Message' }).fill(`${subject} gövdesi`)
    const named = bobMail.getByRole('dialog', { name: subject })
    if (file) {
      await bobMail.locator('input[type="file"]').setInputFiles({ name: 'rapor.txt', mimeType: 'text/plain', buffer: Buffer.from('rapor\n') })
      await expect(named.getByText('rapor.txt')).toBeVisible({ timeout: 30_000 })
      await expect(named.getByLabel('Uploading')).toHaveCount(0, { timeout: 60_000 })
    }
    await named.getByRole('button', { name: 'Send', exact: true }).click()
    await expect(bobMail.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })
    // The toast may be the last send's: wait for this composer to close.
    await expect(bobMail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })
  }
  await send(`Bir ${tag}`)
  await send(`İki ${tag}`, true)
  await send(`Üç ${tag}`)

  const subjects = async () => (await mail.getByRole('list', { name: 'Messages' }).getByRole('link').allTextContents()).map((text) => text.match(/(Bir|İki|Üç) /)?.[1])
  await expect(async () => {
    await mail.reload()
    await expect(mail.getByRole('list', { name: 'Messages' }).getByRole('link').nth(2)).toBeVisible({ timeout: 5_000 })
    expect(await subjects()).toEqual(['Üç', 'İki', 'Bir'])
  }).toPass({ timeout: 60_000 })

  // Read one; Unread shows the other two.
  await mail.getByRole('link', { name: new RegExp(`Üç ${tag}`) }).click()
  await expect(mail.frameLocator('iframe[title="Message"]').last().getByText(`Üç ${tag} gövdesi`)).toBeVisible({ timeout: 60_000 })
  await mail.goto(appUrl('mail', '/inbox'))
  await mail.getByRole('button', { name: 'Unread', exact: true }).click()
  await expect.poll(subjects, { timeout: 30_000 }).toEqual(['İki', 'Bir'])
  await expect(mail).toHaveURL(/filter=unread/)

  // Has attachments, then Oldest first, from Filter.
  await mail.getByRole('button', { name: 'Filter', exact: true }).click()
  await mail.getByRole('menuitemcheckbox', { name: 'Has attachments' }).click()
  await expect.poll(subjects, { timeout: 30_000 }).toEqual(['İki'])
  await mail.getByRole('button', { name: 'Filter (1)' }).click()
  await mail.getByRole('menuitemcheckbox', { name: 'Has attachments' }).click()
  await expect.poll(subjects, { timeout: 30_000 }).toEqual(['Üç', 'İki', 'Bir'])
  await mail.getByRole('button', { name: 'Filter', exact: true }).click()
  await mail.getByRole('menuitemradio', { name: 'Oldest first' }).click()
  await expect.poll(subjects, { timeout: 30_000 }).toEqual(['Bir', 'İki', 'Üç'])

  // Opening a message keeps the order; Reset brings the default back.
  await mail.getByRole('link', { name: new RegExp(`İki ${tag}`) }).click()
  await expect(mail).toHaveURL(/sort=oldest/)
  expect(await subjects()).toEqual(['Bir', 'İki', 'Üç'])
  await mail.getByRole('button', { name: 'Reset' }).click()
  await expect.poll(subjects, { timeout: 30_000 }).toEqual(['Üç', 'İki', 'Bir'])

  await aliceContext.close()
  await bobContext.close()
})
