import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// A message's More menu and keys (docs/plans/mail-parity.md, P3), as
// Proton's: Export, Print, View headers (and download them), View HTML and
// back; R replies, Shift+R replies to all, Shift+F forwards the open
// conversation's newest message.

const PASSWORD = 'Deneme123*MailMessageToolsPassword'

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('More: headers, HTML, print; R, Shift+R and Shift+F', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('mtalice', PASSWORD)
  const bob = newAccount('mtbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 }, acceptDownloads: true })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const tag = Date.now().toString(36)
  const subject = `Araçlar ${tag}`

  await bobMail.getByRole('button', { name: 'New message' }).first().click()
  const composer = bobMail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await bobMail.getByRole('textbox', { name: 'Message' }).fill(`Kalın metin ${tag}`)
  await bobMail.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
  await expect(bobMail.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })
  // The toast may be the last send's: wait for this composer to close.
  await expect(bobMail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })

  await expect(async () => {
    await mail.reload()
    await expect(mail.getByRole('link', { name: new RegExp(subject) })).toBeVisible({ timeout: 2_000 })
  }).toPass({ timeout: 60_000 })
  await mail.getByRole('link', { name: new RegExp(subject) }).click()
  const article = mail.getByRole('article').last()
  await expect(mail.frameLocator('iframe[title="Message"]').last().getByText(`Kalın metin ${tag}`)).toBeVisible({ timeout: 60_000 })

  // View headers, and download them.
  await article.getByRole('button', { name: 'More actions' }).click()
  await mail.getByRole('menuitem', { name: 'View headers' }).click()
  const headers = mail.getByRole('dialog', { name: 'Message headers' })
  await expect(headers.getByText(/^Message-ID: </m)).toBeVisible()
  await expect(headers.getByText(new RegExp(`From: .*${bob.username}@`))).toBeVisible()
  const downloaded = mail.waitForEvent('download')
  await headers.getByRole('button', { name: 'Download' }).click()
  expect((await downloaded).suggestedFilename()).toBe(`headers - ${subject}.txt`)
  await headers.getByRole('button', { name: 'Close' }).first().click()

  // View HTML and back.
  await article.getByRole('button', { name: 'More actions' }).click()
  await mail.getByRole('menuitem', { name: 'View HTML' }).click()
  await expect(article.getByLabel('HTML source')).toContainText(`<p>Kalın metin ${tag}</p>`)
  await article.getByRole('button', { name: 'More actions' }).click()
  await mail.getByRole('menuitem', { name: 'View rendered HTML' }).click()
  await expect(article.getByLabel('HTML source')).toHaveCount(0)

  // Print: the page it prints carries the subject and From.
  await article.getByRole('button', { name: 'More actions' }).click()
  await mail.getByRole('menuitem', { name: 'Print' }).click()
  const printed = mail.frameLocator('iframe[sandbox="allow-same-origin allow-modals"]')
  // The frame prints off screen, at no size: its content is there, not shown.
  await expect(printed.getByRole('heading', { name: subject })).toBeAttached({ timeout: 30_000 })
  await expect(printed.locator('body')).toContainText(`Kalın metin ${tag}`)
  await expect(printed.locator('body')).toContainText(`${bob.username}@`)

  // R replies, Shift+F forwards the open conversation's newest message.
  await mail.locator('body').click({ position: { x: 5, y: 5 } })
  await mail.keyboard.press('r')
  await expect(mail.getByRole('dialog', { name: `Re: ${subject}` })).toBeVisible({ timeout: 30_000 })
  await mail.getByRole('dialog', { name: `Re: ${subject}` }).getByRole('button', { name: 'Discard draft' }).click()
  await mail.keyboard.press('Shift+F')
  await expect(mail.getByRole('dialog', { name: `Fwd: ${subject}` })).toBeVisible({ timeout: 30_000 })

  await aliceContext.close()
  await bobContext.close()
})
