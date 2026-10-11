import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Working the message list as in Proton and Gmail: Shift and Ctrl clicks
// and Shift+arrows choose rows, a right click acts on them, moves can be
// undone, rows drop on a folder, shortcuts act on the open conversation;
// the maximised composer dims the app behind it.

const PASSWORD = 'Deneme123*MailListPassword'
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

test('choosing, right-click actions, undo, drag to a folder, shortcuts and the maximised composer', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('lstalice', PASSWORD)
  const bob = newAccount('lstbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext()
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const aliceMail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const tag = Date.now().toString(36)
  const subjects = [1, 2, 3, 4, 5].map((n) => `Liste ${n} ${tag}`)
  for (const subject of subjects) await write(bobMail, `${alice.username}@${domain}`, subject)

  await aliceMail.reload()
  const list = aliceMail.getByRole('list', { name: 'Messages' })
  const row = (subject: string) => list.getByRole('listitem').filter({ hasText: subject })
  await expect(row(subjects[0])).toBeVisible({ timeout: 60_000 })
  // Newest first: 5, 4, 3, 2, 1.

  // Ctrl-click chooses without opening; Shift-click chooses the range.
  await row(subjects[4]).getByRole('link').click({ modifiers: ['ControlOrMeta'] })
  await expect(aliceMail.getByText('1 selected')).toBeVisible()
  await row(subjects[2]).getByRole('link').click({ modifiers: ['Shift'] })
  await expect(aliceMail.getByText('3 selected')).toBeVisible()
  expect(aliceMail.url()).not.toContain(subjects[0])

  // A right click on a chosen row acts on all three: archived, then undone.
  await row(subjects[3]).click({ button: 'right' })
  const menu = aliceMail.getByRole('menu')
  await expect(menu.getByRole('menuitem', { name: /Mark as read/ })).toBeVisible()
  if (SHOTS) await aliceMail.screenshot({ path: `${SHOTS}/list-menu.png` })
  await menu.getByRole('menuitem', { name: /^Archive/ }).click()
  await expect(aliceMail.getByText('3 messages archived.')).toBeVisible({ timeout: 30_000 })
  await expect(row(subjects[3])).toHaveCount(0)
  await aliceMail.getByRole('button', { name: 'Undo' }).click()
  await expect(row(subjects[3])).toBeVisible({ timeout: 30_000 })
  await expect(row(subjects[4])).toBeVisible()

  // A right click on another row acts on that row alone.
  await row(subjects[0]).click({ button: 'right' })
  await aliceMail.getByRole('menu').getByRole('menuitem', { name: /^Star/ }).click()
  await expect(row(subjects[0]).getByRole('button', { name: 'Remove star' })).toBeVisible({ timeout: 30_000 })

  // Keyboard: open the newest, X chooses it, Shift+Down chooses the next too.
  await row(subjects[4]).getByRole('link').click()
  await aliceMail.locator('body').press('Escape')
  await aliceMail.keyboard.press('j')
  await expect(aliceMail).toHaveURL(/\/inbox\/.+/)
  await aliceMail.keyboard.press('Shift+ArrowDown')
  await expect(aliceMail.getByText('2 selected')).toBeVisible()
  await aliceMail.keyboard.press('Escape')
  await expect(aliceMail.getByText('2 selected')).toHaveCount(0)

  // T moves the open conversation to the Trash.
  await row(subjects[1]).getByRole('link').click()
  await expect(aliceMail.getByRole('heading', { name: subjects[1] })).toBeVisible({ timeout: 30_000 })
  await aliceMail.keyboard.press('t')
  await expect(aliceMail.getByText('Moved to Trash.')).toBeVisible({ timeout: 30_000 })
  await expect(row(subjects[1])).toHaveCount(0)

  // A row dragged onto Archive is archived.
  await row(subjects[2]).dragTo(aliceMail.getByRole('link', { name: /^Archive/ }))
  await expect(aliceMail.getByText('Archived.')).toBeVisible({ timeout: 30_000 })
  await aliceMail.getByRole('link', { name: /^Archive/ }).click()
  await expect(row(subjects[2])).toBeVisible({ timeout: 30_000 })

  // ? lists the shortcuts.
  await aliceMail.keyboard.press('Shift+?')
  await expect(aliceMail.getByRole('dialog', { name: 'Keyboard shortcuts' })).toBeVisible()
  if (SHOTS) await aliceMail.screenshot({ path: `${SHOTS}/shortcuts.png` })
  await aliceMail.keyboard.press('Escape')

  // The maximised composer dims the app; a click beside it docks it again.
  await aliceMail.getByRole('button', { name: 'New message' }).first().click()
  const composer = aliceMail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('button', { name: 'Maximise' }).click()
  if (SHOTS) await aliceMail.screenshot({ path: `${SHOTS}/composer-maximised.png` })
  await aliceMail.mouse.click(10, 450)
  await expect(composer.getByRole('button', { name: 'Maximise' })).toBeVisible()

  await aliceContext.close()
  await bobContext.close()
})
