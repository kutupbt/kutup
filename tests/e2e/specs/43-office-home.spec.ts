import { expect, test } from '@playwright/test'
import { appOrigin, appUrl, newAccount, registerAccount } from '../fixtures/apps'

const PASSWORD = 'Deneme123*OfficeHomePassword'

test('the Office home starts a document in Drive and lists it afterwards', async ({ browser }) => {
  test.slow()
  const account = newAccount('officehome', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, account)
  const page = await context.newPage()

  await page.goto(appUrl('office'))
  await expect(page.getByRole('heading', { name: 'Start something new' })).toBeVisible({ timeout: 120_000 })
  await expect(page.getByText('Nothing here yet')).toBeVisible({ timeout: 60_000 })

  // A new note is an ordinary Drive file: it opens in Drive's editor.
  await page.getByTestId('office-new-note').click()
  await page.waitForURL((url) => url.origin === appOrigin('drive') && url.pathname.startsWith('/file/'), { timeout: 60_000 })
  const editor = page.url()
  // Drive signs itself in through the account app first; let it settle.
  await expect(page.getByRole('link', { name: 'Back to My files' })).toBeVisible({ timeout: 120_000 })
  expect(page.url()).toBe(editor)

  await page.goto(appUrl('office'))
  const cards = page.getByTestId('office-document')
  await expect(cards).toHaveCount(1, { timeout: 60_000 })
  await expect(cards).toContainText('Untitled note.md')
  await expect(cards).toHaveAttribute('href', editor)

  // The kinds in the sidebar narrow the list.
  await page.getByRole('link', { name: 'Spreadsheets' }).click()
  await expect(page.getByText('Nothing here yet')).toBeVisible()
  await page.getByRole('link', { name: 'Notes' }).click()
  await expect(cards).toHaveCount(1)

  await page.getByRole('searchbox', { name: 'Search by name' }).fill('budget')
  await expect(page.getByText('No match')).toBeVisible()

  await context.close()
})
