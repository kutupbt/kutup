import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Folders and labels (docs/plans/mail-filters.md, F1): made from the
// sidebar, nested, mail moved with Move to and labelled with Label as,
// dropped on a folder, filed with Undo; deleting a folder keeps its mail in
// Archive. Names never reach the server in clear.

const PASSWORD = 'Deneme123*MailFoldersPassword'
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

test('folders and labels: make, nest, file, label, drop, delete', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('fldalice', PASSWORD)
  const bob = newAccount('fldbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext()
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const tag = Date.now().toString(36)
  const subjects = [1, 2, 3].map((n) => `Klasör ${n} ${tag}`)
  for (const subject of subjects) await write(bobMail, `${alice.username}@${domain}`, subject)

  // The server only ever sees sealed names.
  const plainNames: string[] = []
  mail.on('request', (r) => {
    if (/\/api\/mail\/(folders|labels)/.test(r.url()) && r.method() !== 'GET') plainNames.push(r.postData() ?? '')
  })

  // A folder, and one inside it, from the sidebar.
  const nav = mail.getByRole('navigation')
  await nav.getByRole('button', { name: 'New folder' }).click()
  let dialog = mail.getByRole('dialog', { name: 'New folder' })
  await dialog.getByLabel('Folder name').fill('İş')
  await dialog.getByRole('button', { name: 'Save' }).click()
  await expect(nav.getByRole('link', { name: 'İş' })).toBeVisible({ timeout: 30_000 })
  await nav.getByRole('link', { name: 'İş' }).hover()
  await nav.getByRole('button', { name: 'Options for İş' }).click()
  await mail.getByRole('menuitem', { name: 'New folder inside' }).click()
  dialog = mail.getByRole('dialog', { name: 'New folder' })
  await dialog.getByLabel('Folder name').fill('Müşteriler')
  await dialog.getByRole('button', { name: 'Save' }).click()
  await expect(nav.getByRole('link', { name: 'Müşteriler' })).toBeVisible({ timeout: 30_000 })
  // A sibling with the same name is refused in the browser.
  await nav.getByRole('button', { name: 'New folder' }).click()
  dialog = mail.getByRole('dialog', { name: 'New folder' })
  await dialog.getByLabel('Folder name').fill('iş')
  await dialog.getByRole('button', { name: 'Save' }).click()
  await expect(dialog.getByText('A folder with this name is already there.')).toBeVisible()
  await dialog.getByRole('button', { name: 'Cancel' }).click()
  // A label.
  await nav.getByRole('button', { name: 'New label' }).click()
  dialog = mail.getByRole('dialog', { name: 'New label' })
  await dialog.getByLabel('Label name').fill('Faturalar')
  await dialog.getByRole('button', { name: 'Save' }).click()
  await expect(nav.getByRole('link', { name: 'Faturalar' })).toBeVisible({ timeout: 30_000 })
  expect(plainNames.length).toBeGreaterThan(0)
  for (const body of plainNames) {
    expect(body).not.toContain('İş')
    expect(body).not.toContain('Müşteriler')
    expect(body).not.toContain('Faturalar')
  }

  // Move to (M) puts the open message into Müşteriler; Undo brings it back.
  await mail.goto(appUrl('mail', '/inbox'))
  const list = mail.getByRole('list', { name: 'Messages' })
  const row = (subject: string) => list.getByRole('listitem').filter({ hasText: subject })
  await row(subjects[0]).getByRole('link').click()
  await expect(mail.getByRole('heading', { name: subjects[0] })).toBeVisible({ timeout: 30_000 })
  await mail.keyboard.press('m')
  const picker = mail.getByRole('dialog', { name: 'Move to' })
  await picker.getByRole('searchbox').fill('müş')
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/move-to.png` })
  await picker.getByRole('button', { name: 'Müşteriler' }).click()
  await expect(mail.getByText('Moved to Müşteriler.')).toBeVisible({ timeout: 30_000 })
  await expect(row(subjects[0])).toHaveCount(0)
  await mail.getByRole('button', { name: 'Undo' }).click()
  await expect(row(subjects[0])).toBeVisible({ timeout: 30_000 })

  // Label as from the right click; the chip shows on the row.
  await row(subjects[1]).click({ button: 'right' })
  await mail.getByRole('menuitem', { name: /Label as/ }).click()
  await mail.getByRole('menuitem', { name: 'Faturalar' }).click()
  await expect(row(subjects[1]).getByText('Faturalar')).toBeVisible({ timeout: 30_000 })

  // A row dropped on İş is filed there; İş lists it.
  await row(subjects[2]).dragTo(nav.getByRole('link', { name: 'İş' }))
  await expect(mail.getByText('Moved to İş.')).toBeVisible({ timeout: 30_000 })
  await nav.getByRole('link', { name: 'İş' }).click()
  await expect(mail.getByRole('heading', { name: 'İş' })).toBeVisible()
  await expect(row(subjects[2])).toBeVisible({ timeout: 30_000 })
  // The label lists its mail too.
  await nav.getByRole('link', { name: 'Faturalar' }).click()
  await expect(row(subjects[1])).toBeVisible({ timeout: 30_000 })
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/label-view.png` })

  // Settings lists them; deleting İş (and Müşteriler in it) keeps the mail in Archive.
  await mail.goto(appUrl('mail', '/settings/folders'))
  await expect(mail.getByRole('heading', { name: 'Folders and labels' })).toBeVisible()
  if (SHOTS) await mail.screenshot({ path: `${SHOTS}/folders-settings.png` })
  await mail.getByRole('region', { name: 'Folders' }).getByRole('listitem').filter({ hasText: 'İş' }).getByRole('button', { name: 'Delete folder' }).click()
  const confirm = mail.getByRole('alertdialog')
  await expect(confirm.getByText('İş and the folders in it are deleted. Their mail is not: it moves to Archive.')).toBeVisible()
  await confirm.getByRole('button', { name: 'Delete' }).click()
  await expect(mail.getByText('İş removed.')).toBeVisible({ timeout: 30_000 })
  await expect(nav.getByRole('link', { name: 'İş' })).toHaveCount(0)
  await expect(nav.getByRole('link', { name: 'Müşteriler' })).toHaveCount(0)
  await nav.getByRole('link', { name: /^Archive/ }).click()
  await expect(row(subjects[2])).toBeVisible({ timeout: 30_000 })

  await aliceContext.close()
  await bobContext.close()
})
