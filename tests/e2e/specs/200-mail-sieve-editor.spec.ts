import { expect, test, type BrowserContext, type Locator, type Page } from '../fixtures/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// The Sieve editor (docs/plans/mail-sieve-editor.md): a filter written as one
// Sieve script in Settings → Filters, checked as it is typed, saved as the
// filter Kutup runs, filing new mail, and opened again as the same rule.

const PASSWORD = 'Deneme123*MailSieveEditorPassword'

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
  await expect(page.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })
}

/** Replaces the whole script in the editor, as one paste. */
async function replaceScript(page: Page, editor: Locator, script: string) {
  await editor.click()
  await page.keyboard.press('ControlOrMeta+a')
  await page.keyboard.insertText(script)
}

test('a filter written as Sieve: checked, saved, filing mail, and opened again as Sieve', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('sevalice', PASSWORD)
  const bob = newAccount('sevbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext()
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const from = `${bob.username}@${domain}`
  const tag = Date.now().toString(36)

  await mail.goto(appUrl('mail', '/settings/filters'))
  await expect(mail.getByRole('heading', { name: 'Filters' })).toBeVisible({ timeout: 120_000 })
  await mail.getByRole('button', { name: 'Add Sieve filter' }).click()
  const dialog = mail.getByTestId('sieve-filter-dialog')
  await expect(dialog.getByRole('heading', { name: 'Add Sieve filter' })).toBeVisible()
  const editor = dialog.getByRole('textbox', { name: 'Sieve script' })
  const problems = dialog.getByTestId('sieve-filter-problems')
  const save = dialog.getByRole('button', { name: 'Save' })
  await dialog.getByLabel('Filter name').fill('Bob arşive')

  // The template holds no filter yet: nothing to save.
  await expect(editor).toContainText('require ["fileinto", "imap4flags"];')
  await expect(problems).toHaveText('There is no filter in this script yet.')
  await expect(save).toBeDisabled()

  // An auto-reply is not a filter: the check names where it lives instead.
  await replaceScript(mail, editor, `require ["vacation"];\n\nif address :all :is "From" "${from}" {\n    vacation "Tatildeyim";\n}\n`)
  await expect(problems).toContainText("Kutup's filters don't send replies: use Settings → Auto-reply.")
  await expect(save).toBeDisabled()

  // One filter Kutup can hold: valid, and saved.
  await replaceScript(
    mail,
    editor,
    `require ["fileinto", "imap4flags"];\n\nif address :all :is "From" "${from}" {\n    fileinto "archive";\n    addflag "\\\\Flagged";\n}\n`,
  )
  await expect(problems).toHaveText('')
  await expect(save).toBeEnabled()
  await save.click()
  await expect(mail.getByText('Filter Bob arşive created.')).toBeVisible({ timeout: 30_000 })
  await expect(dialog).toHaveCount(0)

  // After a reload the filter is listed, as the rule it is.
  await mail.reload()
  const listed = mail.getByRole('listitem').filter({ hasText: 'Bob arşive' })
  await expect(listed).toBeVisible({ timeout: 60_000 })
  await expect(listed).toContainText(from)

  // Bob's mail goes straight to Archive, starred.
  await write(bobMail, `${alice.username}@${domain}`, `Sieve ${tag}`)
  await mail.goto(appUrl('mail'))
  const nav = mail.getByRole('navigation')
  await nav.getByRole('link', { name: /^Archive/ }).click()
  const row = mail.getByRole('list', { name: 'Messages' }).getByRole('listitem').filter({ hasText: `Sieve ${tag}` })
  await expect(row).toBeVisible({ timeout: 60_000 })
  await expect(row.getByRole('button', { name: 'Remove star' })).toBeVisible()

  // Opened again as Sieve: the same rule, valid as it stands.
  await mail.goto(appUrl('mail', '/settings/filters'))
  await mail.getByRole('listitem').filter({ hasText: 'Bob arşive' }).getByRole('button', { name: 'Edit as Sieve' }).click()
  const again = mail.getByTestId('sieve-filter-dialog')
  await expect(again.getByRole('heading', { name: 'Edit filter as Sieve' })).toBeVisible()
  const script = again.getByRole('textbox', { name: 'Sieve script' })
  await expect(script).toContainText(from)
  await expect(script).toContainText('fileinto "archive";')
  await expect(script).toContainText('addflag "\\\\Flagged";')
  await expect(again.getByTestId('sieve-filter-problems')).toHaveText('')
  await expect(again.getByRole('button', { name: 'Save' })).toBeEnabled()

  await aliceContext.close()
  await bobContext.close()
})
