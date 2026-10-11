import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Appearance (docs/plans/mail-parity.md, P2), as Proton's Layouts: the
// reading pane beside or below the list, compact rows, a composer that
// opens maximised; the list resizes with its handle.

const PASSWORD = 'Deneme123*MailAppearancePassword'
const SHOTS = process.env.MAIL_UX_SHOTS

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('appearance: row layout, compact rows, maximised composer, resizable list', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('apalice', PASSWORD)
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await registerAccount(context, alice)
  const mail = await openMail(context)
  const tag = Date.now().toString(36)

  // A message to herself, so the list has a row.
  await mail.getByRole('button', { name: 'New message' }).first().click()
  let composer = mail.getByRole('dialog', { name: 'New message' })
  await expect(composer).not.toHaveAttribute('aria-modal', 'true')
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  const subject = `Görünüm ${tag}`
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await mail.getByRole('textbox', { name: 'Message' }).fill('gövde')
  await mail.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
  await expect(mail.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })
  const row = mail.getByRole('listitem').filter({ has: mail.getByRole('link', { name: new RegExp(subject) }) }).first()
  await expect(row).toBeVisible({ timeout: 60_000 })
  const comfortable = (await row.boundingBox())!.height

  // The column layout: the list resizes with its handle, by keyboard too.
  const list = mail.getByRole('region', { name: 'Inbox' })
  const handle = mail.getByRole('separator', { name: 'Resize the list' })
  await expect(handle).toHaveAttribute('aria-orientation', 'vertical')
  const before = (await list.boundingBox())!.width
  await handle.focus()
  await mail.keyboard.press('Shift+ArrowRight')
  await expect.poll(async () => (await list.boundingBox())!.width).toBeGreaterThan(before + 50)

  // Row, compact, maximised.
  await mail.goto(appUrl('mail', '/settings/appearance'))
  const pick = async (group: string, name: string) => {
    await mail.getByRole('radiogroup', { name: group }).getByRole('radio', { name }).click()
    await expect(mail.getByRole('radiogroup', { name: group }).getByRole('radio', { name })).toHaveAttribute('aria-checked', 'true', { timeout: 30_000 })
  }
  await pick('Inbox layout', 'Row')
  await pick('Density', 'Compact')
  await pick('Composer', 'Maximized')
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/appearance-settings.png` })

  await mail.goto(appUrl('mail', '/inbox'))
  await expect(row).toBeVisible({ timeout: 60_000 })
  await expect(handle).toHaveAttribute('aria-orientation', 'horizontal')
  expect((await row.boundingBox())!.height).toBeLessThan(comfortable)
  // The message opens below the list.
  await mail.getByRole('link', { name: new RegExp(subject) }).click()
  const article = mail.getByRole('article').first()
  await expect(article).toBeVisible({ timeout: 60_000 })
  expect((await article.boundingBox())!.y).toBeGreaterThan((await list.boundingBox())!.y + (await list.boundingBox())!.height - 1)
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/appearance-row-compact.png` })
  // A new message opens maximised.
  await mail.getByRole('button', { name: 'New message' }).first().click()
  composer = mail.getByRole('dialog', { name: 'New message' })
  await expect(composer).toHaveAttribute('aria-modal', 'true')

  await context.close()
})
