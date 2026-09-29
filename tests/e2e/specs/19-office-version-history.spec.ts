import { expect, test } from '@playwright/test'
import { editorCanvases, freshOfficeFile, officeReady, openOffice, write } from '../fixtures/office'

const PASSWORD = 'Deneme123*OfficeHistoryPassword'

test('Spreadsheet: two saves make two versions; restoring one reopens the editor', async ({ browser }) => {
  test.slow()
  const { context, url } = await freshOfficeFile(browser, 'Spreadsheet', PASSWORD)
  const tab = await openOffice(context, url)
  const save = tab.page.getByRole('button', { name: 'Save', exact: true })

  for (const [text, at] of [
    ['first', { x: 162, y: 237 }],
    ['second', { x: 162, y: 256 }],
  ] as const) {
    await write(tab, 'Spreadsheet', text, at)
    await tab.page.keyboard.press('Enter')
    const saved = tab.page.waitForResponse((response) => response.request().method() !== 'GET' && /\/api\/files\/[^/]+(\/versions)?/.test(new URL(response.url()).pathname) && response.ok())
    await save.click()
    await saved
  }

  await tab.page.getByRole('button', { name: 'History', exact: true }).click()
  const history = tab.page.getByRole('complementary').filter({ has: tab.page.getByRole('heading', { name: 'Version history' }) })
  await expect(history).toBeVisible()
  const restore = history.getByRole('button', { name: 'Restore', exact: true })
  await expect.poll(() => restore.count(), { timeout: 30_000 }).toBeGreaterThanOrEqual(2)

  const since = tab.logs.length
  await restore.last().click()
  const dialog = tab.page.getByRole('dialog').filter({ hasText: 'Restore this version?' })
  await expect(dialog).toBeVisible()
  await dialog.getByRole('button', { name: 'Save & restore' }).click()
  await officeReady(tab, since)
  expect(await editorCanvases(tab.page)).toBeGreaterThan(0)
  await context.close()
})
