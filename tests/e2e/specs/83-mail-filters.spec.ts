import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Filters (docs/plans/mail-filters.md, F2): built in Settings with Proton's
// four steps, applied to the mail already there, filing new mail as it
// arrives; "Always move sender's emails" from Move to.

const PASSWORD = 'Deneme123*MailFiltersPassword'
const SHOTS = process.env.MAIL_UX_SHOTS

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

async function write(page: Page, to: string, subject: string) {
  await page.getByRole('button', { name: 'New message' }).first().click()
  const composer = page.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(to)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await page.getByRole('textbox', { name: 'Message' }).fill(`${subject} gövdesi`)
  await page.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
  await expect(page.getByText('Message sent').first()).toBeVisible({ timeout: 60_000 })
}

test('filters: built in four steps, applied to existing mail, filing new mail; always move a sender', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('fltalice', PASSWORD)
  const bob = newAccount('fltbob', PASSWORD)
  const carol = newAccount('fltcarol', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext()
  const carolContext = await browser.newContext()
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  await registerAccount(carolContext, carol)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const carolMail = await openMail(carolContext)
  const to = `${alice.username}@${domain}`
  const tag = Date.now().toString(36)
  const list = mail.getByRole('list', { name: 'Messages' })
  const row = (subject: string) => list.getByRole('listitem').filter({ hasText: subject })

  // An invoice from before the filter exists.
  await write(bobMail, to, `Eylül Faturası ${tag}`)

  // A folder for invoices.
  const nav = mail.getByRole('navigation')
  await nav.getByRole('button', { name: 'New folder' }).click()
  const folderDialog = mail.getByRole('dialog', { name: 'New folder' })
  await folderDialog.getByLabel('Folder name').fill('Faturalar')
  await folderDialog.getByRole('button', { name: 'Save' }).click()
  await expect(nav.getByRole('link', { name: 'Faturalar' })).toBeVisible({ timeout: 30_000 })

  // Settings → Filters: Name, Conditions, Actions, Preview.
  await mail.getByRole('link', { name: 'Settings' }).click()
  await mail.getByRole('link', { name: 'Filters' }).click()
  await mail.getByRole('button', { name: 'Add filter' }).click()
  const wizard = mail.getByRole('dialog', { name: 'Add filter' })
  await wizard.getByLabel('Filter name').fill('Faturalar')
  await wizard.getByRole('button', { name: 'Next' }).click()
  await wizard.getByRole('textbox', { name: 'Value' }).fill('FATURA')
  await wizard.getByRole('button', { name: 'Next' }).click()
  await wizard.getByRole('combobox', { name: 'Move to' }).click()
  await mail.getByRole('option', { name: 'Faturalar' }).click()
  await wizard.getByRole('checkbox', { name: 'Starred' }).click()
  await wizard.getByRole('button', { name: 'Next' }).click()
  await expect(wizard.getByText('If the subject contains “FATURA”: move to Faturalar, star.')).toBeVisible()
  await wizard.getByRole('checkbox', { name: 'Apply filter to existing mail' }).click()
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/filter-preview.png` })
  await wizard.getByRole('button', { name: 'Save' }).click()
  await expect(mail.getByText('Faturalar created.')).toBeVisible({ timeout: 30_000 })
  await expect(mail.getByRole('listitem').filter({ hasText: 'If the subject contains' })).toBeVisible()
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/filters-settings.png` })

  // The older invoice is filed (in the background), starred.
  await nav.getByRole('link', { name: 'Faturalar' }).click()
  await expect(row(`Eylül Faturası ${tag}`)).toBeVisible({ timeout: 60_000 })
  await expect(row(`Eylül Faturası ${tag}`).getByRole('button', { name: 'Remove star' })).toBeVisible()

  // A new invoice goes straight there; other mail stays in the Inbox.
  await write(bobMail, to, `Ekim faturası ${tag}`)
  await write(bobMail, to, `Merhaba ${tag}`)
  await mail.reload()
  await expect(row(`Ekim faturası ${tag}`)).toBeVisible({ timeout: 60_000 })
  await nav.getByRole('link', { name: /^Inbox/ }).click()
  await expect(row(`Merhaba ${tag}`)).toBeVisible({ timeout: 60_000 })
  await expect(row(`Ekim faturası ${tag}`)).toHaveCount(0)

  // "Always move sender's emails": Carol's mail is moved, and so is her next.
  await write(carolMail, to, `Bülten 1 ${tag}`)
  await mail.reload()
  await row(`Bülten 1 ${tag}`).getByRole('link').click()
  await expect(mail.getByRole('heading', { name: `Bülten 1 ${tag}` })).toBeVisible({ timeout: 30_000 })
  await mail.keyboard.press('m')
  const picker = mail.getByRole('dialog', { name: 'Move to' })
  await picker.getByRole('checkbox', { name: 'Always move sender’s emails' }).click()
  await picker.getByRole('button', { name: 'Archive' }).click()
  await expect(mail.getByText(`Mail from ${carol.username}@${domain} will be moved to Archive.`)).toBeVisible({ timeout: 30_000 })
  await write(carolMail, to, `Bülten 2 ${tag}`)
  await nav.getByRole('link', { name: /^Archive/ }).click()
  await expect(row(`Bülten 2 ${tag}`)).toBeVisible({ timeout: 60_000 })
  // The filter is listed, made from the sender.
  await mail.goto(appUrl('mail', '/settings/filters'))
  await expect(mail.getByText(`If any of the sender is exactly “${carol.username}@${domain}”: move to Archive.`)).toBeVisible()

  await aliceContext.close()
  await bobContext.close()
  await carolContext.close()
})
