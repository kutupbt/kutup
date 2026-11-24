import { mkdir, writeFile } from 'node:fs/promises'
import { expect, test, type Page } from '../fixtures/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { createFolder, item, itemAction } from '../fixtures/drive'

// Search filters beside the type filter: modified, location, created by
// and shared by me. Names are matched in the browser, and so are these;
// the filters stay in the URL, so a reload keeps them.

const PASSWORD = 'Deneme123*DriveSearchFilters'

async function upload(page: Page, path: string) {
  await page.getByRole('button', { name: 'New' }).first().click()
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), page.getByRole('menuitem', { name: 'Upload files' }).click()])
  await chooser.setFiles(path)
}

const heading = (page: Page) => page.getByRole('heading', { name: /results? for “/ })

async function choose(page: Page, filter: string, option: string) {
  await page.getByTestId(`search-filter-${filter}`).click()
  await page.getByRole('menuitemradio', { name: option, exact: true }).click()
}

test('search results narrow by when, where, who and what is shared', async ({ browser }, testInfo) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('searchfilters', PASSWORD))
  const page = await openDrive(context)
  const dir = testInfo.outputPath('files')
  await mkdir(dir, { recursive: true })
  await writeFile(`${dir}/budget-2026.svg`, '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>\n')

  await upload(page, `${dir}/budget-2026.svg`)
  await expect(item(page, 'budget-2026.svg')).toBeVisible({ timeout: 60_000 })
  await createFolder(page, 'budget-archive')
  await itemAction(page, 'budget-archive', 'Get public link')
  await expect(page.getByRole('dialog').getByRole('textbox')).toHaveValue(/#v1\./, { timeout: 30_000 })
  await page.keyboard.press('Escape')

  await page.getByRole('searchbox', { name: 'Search Drive' }).fill('budget')
  await expect(heading(page)).toHaveText('2 results for “budget”', { timeout: 60_000 })

  // Shared by me: only the folder with its link.
  await page.getByTestId('search-filter-shared').click()
  await expect(heading(page)).toHaveText('1 result for “budget”', { timeout: 30_000 })
  await expect(item(page, 'budget-archive')).toBeVisible()
  await expect(page).toHaveURL(/[?&]shared=me/)
  // Kept by a reload, and by changing the query.
  await page.reload()
  await expect(heading(page)).toHaveText('1 result for “budget”', { timeout: 60_000 })
  await expect(page.getByTestId('search-filter-shared')).toHaveAttribute('aria-pressed', 'true')
  await page.getByRole('searchbox', { name: 'Search Drive' }).fill('budget archive')
  await expect(heading(page)).toHaveText('1 result for “budget archive”', { timeout: 30_000 })
  await expect(page).toHaveURL(/[?&]shared=me/)
  await page.getByTestId('search-filter-clear').click()
  await page.getByRole('searchbox', { name: 'Search Drive' }).fill('budget')
  await expect(heading(page)).toHaveText('2 results for “budget”', { timeout: 30_000 })

  // Everything here was made today, by this account, in My files.
  await choose(page, 'modified', 'Today')
  await choose(page, 'created-by', 'Me')
  await choose(page, 'place', 'My files')
  await expect(heading(page)).toHaveText('2 results for “budget”')
  await choose(page, 'place', 'Shared with me')
  await expect(heading(page)).toHaveText('0 results for “budget”')
  await expect(page.getByText('No file or folder name contains “budget” with these filters.')).toBeVisible()
  await choose(page, 'place', 'Any')
  await choose(page, 'created-by', 'Others')
  await expect(heading(page)).toHaveText('0 results for “budget”')
  await page.getByTestId('search-filter-clear').click()
  await expect(heading(page)).toHaveText('2 results for “budget”')

  // Details from the results: where the file is.
  await itemAction(page, 'budget-2026.svg', 'Details')
  await expect(page.getByTestId('details-location')).toHaveText('My files')
  await context.close()
})
