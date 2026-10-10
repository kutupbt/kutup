import { expect, test, type Page } from '@playwright/test'
import { appOrigin, appUrl, newAccount, openDrive, registerAccount, signInAsAdmin } from '../fixtures/apps'
import { createFolder, createNote, item, itemAction, noteLive, openItem, typeAtEnd } from '../fixtures/drive'
import { createOffice, editorCanvases, openOffice } from '../fixtures/office'

const PASSWORD = 'Deneme123*PublicLinksPassword'

/** Makes a public link from the open file page's Share dialog; returns it. */
async function makeFileLink(page: Page): Promise<string> {
  await page.getByRole('button', { name: 'Share', exact: true }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByRole('button', { name: 'Create a public link' }).click()
  const link = dialog.getByTestId('new-file-link')
  await expect(link).toBeVisible({ timeout: 30_000 })
  const url = await link.inputValue()
  await page.keyboard.press('Escape')
  return url
}

/** The bar every public page shows: who shared it, and that nobody checked it. */
async function expectSharedBy(page: Page, username: string) {
  const notice = page.getByTestId('public-notice')
  await expect(notice).toBeVisible({ timeout: 60_000 })
  // The owner's address on this server (username@domain).
  await expect(notice).toContainText(new RegExp(`Shared publicly by ${username}@[a-z0-9.-]+\\.`))
  await expect(notice).toContainText('Never type a password')
}

test('a note shared by link opens on Office, read-only, saying who shared it', async ({ browser }) => {
  test.slow()
  const alice = newAccount('pubnote', PASSWORD)
  const owner = await browser.newContext()
  await registerAccount(owner, alice)
  const drive = await openDrive(owner)
  await createNote(drive)
  await noteLive(drive)
  await typeAtEnd(drive, 'Hello from a public note')
  // Saved as the note's state, which the link serves.
  const saved = drive.waitForResponse((r) => r.request().method() === 'POST' && /\/api\/files\/[^/]+\/versions$/.test(new URL(r.url()).pathname))
  await drive.keyboard.press('Control+s')
  expect((await saved).ok()).toBe(true)

  const link = await makeFileLink(drive)
  expect(link.startsWith(`${appOrigin('office')}/s/`)).toBe(true)
  expect(link).toContain('#key=')

  // Anyone: no account in this browser.
  const visitor = await browser.newContext()
  const page = await visitor.newPage()
  await page.goto(link)
  await expectSharedBy(page, alice.username)
  await expect(page.locator('.prose')).toContainText('Hello from a public note', { timeout: 60_000 })
  await expect(page.locator('.cm-content')).toHaveCount(0)

  // The same link at Drive's address (as made before documents moved) lands here.
  const token = new URL(link).pathname.split('/')[2]
  await page.goto(appUrl('drive', `/s/${token}${new URL(link).hash}`))
  await expect(page).toHaveURL(new RegExp(`^${appOrigin('office')}/s/${token}`), { timeout: 60_000 })
  await expect(page.locator('.prose')).toContainText('Hello from a public note', { timeout: 60_000 })

  // Without its key, nothing opens.
  await page.goto(link.split('#')[0])
  await expect(page.getByText('This link is incomplete')).toBeVisible({ timeout: 60_000 })

  await visitor.close()
  await owner.close()
})

test('a document shared by link opens in ONLYOFFICE without an account', async ({ browser }) => {
  test.slow()
  const alice = newAccount('pubdoc', PASSWORD)
  const owner = await browser.newContext()
  await registerAccount(owner, alice)
  const drive = await openDrive(owner)
  await createOffice(drive, 'Document')
  const link = await makeFileLink(drive)
  expect(link.startsWith(`${appOrigin('office')}/s/`)).toBe(true)

  const visitor = await browser.newContext()
  const tab = await openOffice(visitor, link)
  await expectSharedBy(tab.page, alice.username)
  expect(await editorCanvases(tab.page)).toBeGreaterThan(0)
  // A viewer: nothing to save.
  await expect(tab.page.getByRole('button', { name: 'Save', exact: true })).toHaveCount(0)

  await visitor.close()
  await owner.close()
})

test("a folder's link lists in Drive and opens its documents on Office", async ({ browser }) => {
  test.slow()
  const alice = newAccount('pubfolder', PASSWORD)
  const owner = await browser.newContext()
  await registerAccount(owner, alice)
  const drive = await openDrive(owner)
  const folder = `Public ${Date.now()}`
  await createFolder(drive, folder)
  await openItem(drive, folder)
  const note = await createNote(drive)
  await noteLive(drive)
  await drive.goto(appUrl('drive', '/'))
  await itemAction(drive, folder, 'Get public link')
  const dialog = drive.getByRole('dialog')
  const field = dialog.getByRole('textbox')
  await expect(field).toHaveValue(/#key=/, { timeout: 30_000 })
  const link = await field.inputValue()
  expect(link.startsWith(`${appOrigin('drive')}/s/`)).toBe(true)

  const visitor = await browser.newContext()
  const page = await visitor.newPage()
  await page.goto(link)
  await expectSharedBy(page, alice.username)
  await openItem(page, note)
  await expect(page).toHaveURL(new RegExp(`^${appOrigin('office')}/s/[^/]+/[^/#]+#key=`), { timeout: 60_000 })
  await expectSharedBy(page, alice.username)
  await expect(page.locator('.prose')).toBeVisible({ timeout: 60_000 })

  // Back to the folder's list, the key going along.
  await page.getByRole('link', { name: 'Back to the shared folder' }).click()
  await expect(page).toHaveURL(new RegExp(`^${appOrigin('drive')}/s/[^/#]+#key=`), { timeout: 60_000 })
  await expect(item(page, note)).toBeVisible({ timeout: 60_000 })

  await visitor.close()
  await owner.close()
})

test('anyone reports a link; an administrator takes it down', async ({ browser }) => {
  test.slow()
  const alice = newAccount('pubreport', PASSWORD)
  const owner = await browser.newContext()
  await registerAccount(owner, alice)
  const drive = await openDrive(owner)
  await createNote(drive)
  await noteLive(drive)
  const link = await makeFileLink(drive)
  await owner.close()

  // A visitor, without an account, reports it with the whole link.
  const visitor = await browser.newContext()
  const page = await visitor.newPage()
  await page.goto(link)
  await expectSharedBy(page, alice.username)
  await page.getByTestId('public-notice').getByRole('button', { name: 'Report' }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByTestId('report-reason').click()
  await page.getByRole('option', { name: /^Phishing/ }).click()
  await dialog.getByLabel('Details').fill('Asks for my bank password')
  await expect(dialog.getByLabel('Let the administrators open this link')).toBeChecked()
  await dialog.getByRole('button', { name: 'Send report' }).click()
  await expect(dialog.getByText('Report sent')).toBeVisible({ timeout: 30_000 })
  await dialog.getByRole('button', { name: 'Close' }).first().click()

  // The administrator sees it, with the link, and takes the link down.
  const admin = await browser.newContext()
  await signInAsAdmin(admin)
  const reports = await admin.newPage()
  await reports.goto(appUrl('account', '/admin/reports'))
  const card = reports.getByTestId('link-report').filter({ hasText: 'Asks for my bank password' })
  await expect(card).toBeVisible({ timeout: 60_000 })
  await expect(card).toContainText(alice.email)
  await expect(card.getByRole('link', { name: 'Open the link' })).toHaveAttribute('href', link)
  await card.getByRole('button', { name: 'Take link down' }).click()
  await reports.getByRole('alertdialog').getByRole('button', { name: 'Take link down' }).click()
  await expect(card).toBeHidden({ timeout: 30_000 })
  await reports.getByRole('tab', { name: 'Resolved' }).click()
  await expect(reports.getByTestId('link-report').filter({ hasText: 'Asks for my bank password' })).toContainText('Link taken down')
  await admin.close()

  // The visitor's link now says it was removed.
  await page.reload()
  await expect(page.getByText('This link was removed')).toBeVisible({ timeout: 60_000 })
  await visitor.close()
})
