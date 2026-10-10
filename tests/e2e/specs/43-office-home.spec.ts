import { expect, test } from '@playwright/test'
import { appOrigin, appUrl, newAccount, registerAccount } from '../fixtures/apps'

const PASSWORD = 'Deneme123*OfficeHomePassword'

test('the Office home starts a document in Office and lists it afterwards', async ({ browser }) => {
  test.slow()
  const account = newAccount('officehome', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, account)
  const page = await context.newPage()

  await page.goto(appUrl('office'))
  await expect(page.getByRole('heading', { name: 'Start something new' })).toBeVisible({ timeout: 120_000 })
  await expect(page.getByText('Nothing here yet')).toBeVisible({ timeout: 60_000 })

  // A new note is an ordinary Drive file, and it opens here, in Office.
  await page.getByTestId('office-new-note').click()
  await page.waitForURL((url) => url.origin === appOrigin('office') && url.pathname.startsWith('/file/'), { timeout: 60_000 })
  const editor = new URL(page.url())
  await expect(page.locator('.cm-content')).toBeVisible({ timeout: 60_000 })
  // Its back button returns to the Office home.
  await page.getByRole('link', { name: 'Back to Office' }).click()
  await page.waitForURL((url) => url.origin === appOrigin('office') && url.pathname === '/', { timeout: 60_000 })
  const cards = page.getByTestId('office-document')
  await expect(cards).toHaveCount(1, { timeout: 60_000 })
  await expect(cards).toContainText('Untitled note.md')
  await expect(cards).toHaveAttribute('href', editor.pathname)

  // One address per document: Drive opens it in Office too, and the back
  // button there returns to the Drive folder it came from.
  const drive = await context.newPage()
  await drive.goto(appUrl('drive'))
  await drive.getByText('Untitled note.md', { exact: true }).first().dblclick({ timeout: 120_000 })
  await drive.waitForURL((url) => url.origin === appOrigin('office') && url.pathname === editor.pathname, { timeout: 60_000 })
  await expect(drive.locator('.cm-content')).toBeVisible({ timeout: 120_000 })
  await drive.getByRole('link', { name: 'Back to My files' }).click()
  await drive.waitForURL((url) => url.origin === appOrigin('drive') && url.pathname === '/', { timeout: 60_000 })
  // A link to it on Drive, from before, goes to the same address in Office.
  await drive.goto(appUrl('drive', editor.pathname))
  await drive.waitForURL((url) => url.origin === appOrigin('office') && url.pathname === editor.pathname, { timeout: 120_000 })
  await expect(drive.locator('.cm-content')).toBeVisible({ timeout: 60_000 })
  await drive.close()

  // The kinds in the sidebar narrow the list.
  await page.getByRole('link', { name: 'Spreadsheets' }).click()
  await expect(page.getByText('Nothing here yet')).toBeVisible()
  await page.getByRole('link', { name: 'Notes' }).click()
  await expect(cards).toHaveCount(1)

  await page.getByRole('searchbox', { name: 'Search by name' }).fill('budget')
  await expect(page.getByText('No match')).toBeVisible()

  await context.close()
})
