import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Confirm link URLs (docs/plans/mail-parity.md, P3), as Proton's: a link in
// a message that leads outside Kutup shows where it goes first; "Don't ask
// again" turns that off; a message filed as spam always asks, and opens
// only once the reader says they understand the risk.

const PASSWORD = 'Deneme123*MailLinkConfirmPassword'

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('links ask first; Don’t ask again; spam always asks', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('lcalice', PASSWORD)
  const bob = newAccount('lcbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  // Pages opened from links go nowhere.
  await aliceContext.route(/^https:\/\/example\.org\//, (route) => route.fulfill({ contentType: 'text/html', body: '<title>example</title>' }))
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const tag = Date.now().toString(36)
  const subject = `Bağlantı ${tag}`
  const link = `https://example.org/yol-${tag}`

  await bobMail.getByRole('button', { name: 'New message' }).first().click()
  const composer = bobMail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await bobMail.getByRole('textbox', { name: 'Message' }).click()
  await bobMail.keyboard.type(`Bak: ${link} `)
  await bobMail.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
  await expect(bobMail.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })
  // The toast may be the last send's: wait for this composer to close.
  await expect(bobMail.getByRole('button', { name: 'Send', exact: true })).toHaveCount(0, { timeout: 60_000 })

  await expect(async () => {
    await mail.reload()
    await expect(mail.getByRole('link', { name: new RegExp(subject) })).toBeVisible({ timeout: 2_000 })
  }).toPass({ timeout: 60_000 })
  await mail.getByRole('link', { name: new RegExp(subject) }).click()
  const body = mail.frameLocator('iframe[title="Message"]').last()
  await expect(body.getByRole('link', { name: link })).toBeVisible({ timeout: 60_000 })

  // It asks, showing the address; Cancel opens nothing.
  await body.getByRole('link', { name: link }).click()
  let dialog = mail.getByRole('dialog', { name: 'Link confirmation' })
  await expect(dialog.getByTestId('link-url')).toHaveText(link)
  await dialog.getByRole('button', { name: 'Cancel' }).click()
  await expect(dialog).toHaveCount(0)

  // Don't ask again: it opens, and the next click goes straight there.
  await body.getByRole('link', { name: link }).click()
  dialog = mail.getByRole('dialog', { name: 'Link confirmation' })
  await dialog.getByRole('checkbox', { name: "Don't ask again" }).click()
  let opened = aliceContext.waitForEvent('page')
  await dialog.getByRole('button', { name: /^Confirm opening / }).click()
  expect((await opened).url()).toBe(link)
  await expect.poll(async () => (await mail.request.get(apiUrl('/mail/settings'))).status()).toBeLessThan(500)
  await mail.waitForTimeout(500)
  opened = aliceContext.waitForEvent('page')
  await body.getByRole('link', { name: link }).click()
  await opened
  await expect(mail.getByRole('dialog', { name: 'Link confirmation' })).toHaveCount(0)

  // In Spam it always asks, and opens only once the risk is understood.
  await mail.getByRole('button', { name: 'Mark as spam' }).first().click()
  await expect(mail.getByText('Marked as spam.').first()).toBeVisible({ timeout: 30_000 })
  await mail.goto(appUrl('mail', '/spam'))
  await mail.getByRole('link', { name: new RegExp(subject) }).click()
  await mail.frameLocator('iframe[title="Message"]').last().getByRole('link', { name: link }).click()
  dialog = mail.getByRole('dialog', { name: 'Warning: suspected fake website' })
  const confirm = dialog.getByRole('button', { name: /^Confirm opening / })
  await expect(confirm).toBeDisabled()
  await dialog.getByRole('checkbox', { name: 'I understand the risk' }).click()
  opened = aliceContext.waitForEvent('page')
  await confirm.click()
  expect((await opened).url()).toBe(link)

  await aliceContext.close()
  await bobContext.close()
})
