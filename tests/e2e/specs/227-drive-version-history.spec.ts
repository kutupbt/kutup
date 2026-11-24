import { mkdir, writeFile } from 'node:fs/promises'
import { expect, test, type Page } from '../fixtures/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { item, itemAction } from '../fixtures/drive'

// A file's version history in Drive (Proton Drive's "Version history"):
// replacing a file keeps the version before; the history previews an
// earlier one, restores it as the newest (every other version stays), and
// deletes one.

const PASSWORD = 'Deneme123*VersionHistorySpec'

/** An SVG `width` wide, padded to about `bytes` so the versions' sizes differ. */
function svg(width: number, bytes: number): string {
  const body = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20"><rect width="${width}" height="20" fill="#3a7"/></svg>`
  return `<!-- ${'x'.repeat(Math.max(0, bytes - body.length - 10))} -->\n${body}\n`
}

async function upload(page: Page, path: string) {
  await page.getByRole('button', { name: 'New' }).first().click()
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), page.getByRole('menuitem', { name: 'Upload files' }).click()])
  await chooser.setFiles(path)
}

const history = (page: Page) => page.getByTestId('version-history')
const rows = (page: Page) => history(page).getByTestId('version-row')
const row = (page: Page, version: string) => history(page).locator(`[data-testid="version-row"][data-version="${version}"]`)
const currentRow = (page: Page) => history(page).locator('[data-testid="version-row"][data-current="true"]')

async function rowAction(page: Page, target: ReturnType<typeof row>, action: string) {
  await target.getByTestId('version-menu').click()
  await page.getByTestId(action).click()
}

/** The width of the picture Quick Look shows (the SVG's own `width`). */
async function previewWidth(page: Page): Promise<number> {
  const look = page.getByRole('dialog').filter({ has: page.locator('img') })
  const img = look.locator('img').first()
  await expect(img).toBeVisible({ timeout: 30_000 })
  await expect.poll(() => img.evaluate((el: HTMLImageElement) => el.naturalWidth), { timeout: 30_000 }).toBeGreaterThan(0)
  return img.evaluate((el: HTMLImageElement) => el.naturalWidth)
}

test('a replaced file’s earlier version is previewed, restored and deleted from its history', async ({ browser }, testInfo) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('versionhistory', PASSWORD))
  const page = await openDrive(context)
  const dir = testInfo.outputPath('files')
  await mkdir(`${dir}/new`, { recursive: true })
  await writeFile(`${dir}/logo.svg`, svg(40, 3_000))
  await writeFile(`${dir}/new/logo.svg`, svg(80, 9_000))

  // The first upload, then a new version of it (Replace).
  await upload(page, `${dir}/logo.svg`)
  await expect(item(page, 'logo.svg')).toBeVisible({ timeout: 60_000 })
  await upload(page, `${dir}/new/logo.svg`)
  const conflict = page.getByRole('dialog').filter({ hasText: 'is already here' })
  await conflict.getByRole('button', { name: 'Replace' }).click()
  await expect(page.getByRole('region', { name: 'Uploads' }).getByText('Uploads complete')).toBeVisible({ timeout: 60_000 })

  // The history: the new version current, the first upload before it, and
  // how long earlier versions are kept (the owner's setting).
  await itemAction(page, 'logo.svg', 'Version history')
  await expect(history(page).getByText('Current version')).toBeVisible({ timeout: 30_000 })
  await expect(rows(page)).toHaveCount(2)
  await expect(history(page).getByTestId('version-retention')).toContainText(/Earlier versions are kept for \d+ days/)
  await expect(row(page, 'original')).toContainText('First upload')
  await expect(row(page, 'original')).not.toHaveAttribute('data-current', 'true')
  const replacement = await currentRow(page).getAttribute('data-version')
  expect(replacement).not.toBe('original')
  const originalSize = (await row(page, 'original').textContent())?.match(/· (.+)$/)?.[1]
  expect(originalSize).toBeTruthy()

  // Preview the first upload: its own picture, not the current one.
  await rowAction(page, row(page, 'original'), 'version-preview')
  await expect(page.getByText(/^Version from /)).toBeVisible({ timeout: 30_000 })
  expect(await previewWidth(page)).toBe(40)
  await page.keyboard.press('Escape')
  await expect(page.getByText(/^Version from /)).toHaveCount(0)
  await expect(history(page)).toBeVisible()

  // Restore it: it becomes the newest version; the one it replaced stays.
  await rowAction(page, row(page, 'original'), 'version-restore')
  await page.getByRole('alertdialog').getByTestId('version-restore-confirm').click()
  await expect(page.getByText('Version restored')).toBeVisible({ timeout: 60_000 })
  await expect(rows(page)).toHaveCount(3, { timeout: 30_000 })
  await expect(row(page, replacement!)).toBeVisible()
  await expect(currentRow(page)).not.toHaveAttribute('data-version', replacement!)
  await expect(currentRow(page)).not.toHaveAttribute('data-version', 'original')
  await expect(currentRow(page)).toContainText(originalSize!)
  // The file itself shows the restored picture.
  await rowAction(page, currentRow(page), 'version-preview')
  expect(await previewWidth(page)).toBe(40)
  await page.keyboard.press('Escape')

  // Delete the replacement, now an earlier version.
  await rowAction(page, row(page, replacement!), 'version-delete')
  const confirm = page.getByRole('alertdialog', { name: 'Delete this version' })
  await confirm.getByRole('button', { name: 'Delete permanently' }).click()
  await expect(page.getByText('Version deleted')).toBeVisible({ timeout: 30_000 })
  await expect(rows(page)).toHaveCount(2)
  await expect(row(page, replacement!)).toHaveCount(0)

  // As the server has it after a reload.
  await page.reload()
  await itemAction(page, 'logo.svg', 'Version history')
  await expect(rows(page)).toHaveCount(2, { timeout: 30_000 })
  await expect(row(page, 'original')).toBeVisible()
  await context.close()
})
