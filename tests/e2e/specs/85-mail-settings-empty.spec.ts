import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Mail settings and emptying (docs/plans/mail-parity.md, P1), as Proton's:
// All mail in the sidebar with Spam and Trash until "Exclude Spam/Trash
// from All mail"; "Delete all" in Trash; the auto-delete banner's Enable.

const PASSWORD = 'Deneme123*MailSettingsPassword'
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
  // The toast may be the last send's: wait for this composer to close.
  await expect(page.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })
}

test('All mail, Exclude Spam/Trash, Delete all in Trash, and auto-delete', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('setalice', PASSWORD)
  const bob = newAccount('setbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext()
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const tag = Date.now().toString(36)
  const list = mail.getByRole('list', { name: 'Messages' })
  const row = (subject: string) => list.getByRole('listitem').filter({ hasText: subject })
  const nav = mail.getByRole('navigation')
  const kept = `Kalan ${tag}`
  const trashed = `Çöp ${tag}`
  await write(bobMail, `${alice.username}@${domain}`, kept)
  await write(bobMail, `${alice.username}@${domain}`, trashed)

  // One message to the Trash; All mail still shows it, labelled Trash.
  await mail.reload()
  await row(trashed).click({ button: 'right' })
  await mail.getByRole('menuitem', { name: /Move to Trash/ }).click()
  await nav.getByRole('link', { name: /^All mail/ }).click()
  await expect(row(kept)).toBeVisible({ timeout: 30_000 })
  await expect(row(trashed).getByText('Trash')).toBeVisible()

  // Exclude Spam/Trash from All mail.
  await mail.getByRole('link', { name: 'Settings' }).click()
  await expect(mail.getByRole('heading', { name: 'General' })).toBeVisible()
  await mail.getByRole('checkbox', { name: /Exclude Spam\/Trash from All mail/ }).click()
  await expect(mail.getByText('Preference saved.')).toBeVisible({ timeout: 30_000 })
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/general-settings.png` })
  await nav.getByRole('link', { name: /^All mail/ }).click()
  await expect(row(kept)).toBeVisible({ timeout: 30_000 })
  await expect(row(trashed)).toHaveCount(0)

  // Trash: the auto-delete banner offers Enable; Delete all empties it.
  await nav.getByRole('link', { name: /^Trash/ }).click()
  await expect(row(trashed)).toBeVisible({ timeout: 30_000 })
  await expect(mail.getByText('Automatically delete messages that have been in Trash and Spam for more than 30 days.')).toBeVisible()
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/trash-banner.png` })
  await mail.getByRole('button', { name: 'Enable', exact: true }).click()
  await expect(mail.getByText('Messages that have been in Trash and Spam more than 30 days will be automatically deleted.')).toBeVisible({ timeout: 30_000 })
  await mail.getByRole('button', { name: 'Delete all' }).click()
  const confirm = mail.getByRole('alertdialog')
  await expect(confirm.getByText('Delete everything in Trash?')).toBeVisible()
  await confirm.getByRole('button', { name: 'Delete all' }).click()
  await expect(row(trashed)).toHaveCount(0, { timeout: 30_000 })
  await expect(mail.getByRole('button', { name: 'Delete all' })).toHaveCount(0)
  // Settings shows auto-delete on.
  await mail.goto(appUrl('mail', '/settings/general'))
  await expect(mail.getByRole('checkbox', { name: /Auto-delete unwanted messages/ })).toBeChecked()

  await aliceContext.close()
  await bobContext.close()
})
