// Names unique in a folder, and files not uploaded twice
// (docs/plans/drive-unique-names.md):
//   1. the same file uploaded again is skipped; a different one under a
//      taken name (case aside) asks Keep both / Replace / Skip;
//   2. a folder dropped again goes into the folder already there and sends
//      only what changed, asking once with "apply to all";
//   3. renames refuse a taken name, case aside — but Turkish İ keeps its dot;
//   4. items made without hashes (an older client) are filled in when the
//      owner opens the folder, the later duplicate renamed `name (2)`;
//   5. a file restored after its name was taken comes back as `name (2)`.

import { mkdir, writeFile } from 'node:fs/promises'
import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { createFolder, item, itemAction, openItem, openSection, renameItem } from '../fixtures/drive'

const PASSWORD = 'Deneme123*UniqueNamesPassword'

async function upload(page: Page, ...paths: string[]) {
  await page.getByRole('button', { name: 'New' }).first().click()
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), page.getByRole('menuitem', { name: 'Upload files' }).click()])
  await chooser.setFiles(paths)
}

async function uploadFolder(page: Page, dir: string) {
  await page.getByRole('button', { name: 'New' }).first().click()
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), page.getByRole('menuitem', { name: 'Upload folder' }).click()])
  await chooser.setFiles(dir)
}

const panel = (page: Page) => page.getByRole('region', { name: 'Uploads' })
const conflict = (page: Page) => page.getByRole('dialog').filter({ hasText: 'is already here' })

/** Uploads created on the server (tus `POST /api/uploads`). */
function countUploads(page: Page): { count: number } {
  const seen = { count: 0 }
  page.on('request', (r) => {
    if (r.method() === 'POST' && /\/api\/uploads\/?$/.test(new URL(r.url()).pathname)) seen.count++
  })
  return seen
}

async function freshDrive(browser: import('@playwright/test').Browser, label: string): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext()
  await registerAccount(context, newAccount(label, PASSWORD))
  return { context, page: await openDrive(context) }
}

test('the same file again is skipped; a different one under a taken name asks', async ({ browser }, testInfo) => {
  test.slow()
  const { context, page } = await freshDrive(browser, 'uniqueupload')
  const uploads = countUploads(page)
  const dir = testInfo.outputPath('files')
  await mkdir(`${dir}/again`, { recursive: true })
  await mkdir(`${dir}/upper`, { recursive: true })
  await mkdir(`${dir}/third`, { recursive: true })
  await mkdir(`${dir}/fourth`, { recursive: true })
  await writeFile(`${dir}/report.txt`, 'first version')
  await writeFile(`${dir}/again/report.txt`, 'first version')
  await writeFile(`${dir}/upper/REPORT.TXT`, 'a different file')
  await writeFile(`${dir}/third/report.txt`, 'the replacement')
  await writeFile(`${dir}/fourth/report.txt`, 'never sent')

  await upload(page, `${dir}/report.txt`)
  await expect(item(page, 'report.txt')).toBeVisible({ timeout: 60_000 })
  await expect.poll(() => uploads.count).toBe(1)

  // The same bytes under the same name: nothing is sent.
  await upload(page, `${dir}/again/report.txt`)
  await expect(panel(page).getByText('Already in this folder')).toBeVisible({ timeout: 60_000 })
  expect(uploads.count).toBe(1)

  // A different file whose name differs only in case: asked.
  await upload(page, `${dir}/upper/REPORT.TXT`)
  await expect(conflict(page)).toBeVisible({ timeout: 60_000 })
  await expect(conflict(page)).toContainText('“REPORT.TXT” is already here')
  await expect(conflict(page)).toContainText('“REPORT (2).TXT”')
  // One file: nothing to apply to the rest.
  await expect(conflict(page).getByRole('checkbox')).toHaveCount(0)
  await conflict(page).getByRole('button', { name: 'Keep both' }).click()
  await expect(item(page, 'REPORT (2).TXT')).toBeVisible({ timeout: 60_000 })
  await expect(item(page, 'report.txt')).toBeVisible()

  // Replace: the one there goes to the trash, the new one takes its name.
  await upload(page, `${dir}/third/report.txt`)
  await conflict(page).getByRole('button', { name: 'Replace' }).click()
  await expect(panel(page).getByText('Uploads complete')).toBeVisible({ timeout: 60_000 })
  await page.reload()
  await expect(item(page, 'report.txt')).toHaveCount(1, { timeout: 60_000 })
  await expect(item(page, 'report (2).txt')).toHaveCount(0)
  await openSection(page, 'Trash')
  await expect(item(page, 'report.txt')).toBeVisible({ timeout: 30_000 })
  await openSection(page, 'My files')

  // Skip: nothing changes.
  const before = uploads.count
  await upload(page, `${dir}/fourth/report.txt`)
  await conflict(page).getByRole('button', { name: 'Skip' }).click()
  await expect(panel(page).getByText('Skipped')).toBeVisible({ timeout: 30_000 })
  expect(uploads.count).toBe(before)
  await context.close()
})

test('a folder dropped again goes into the one there and sends only what changed', async ({ browser }, testInfo) => {
  test.slow()
  const { context, page } = await freshDrive(browser, 'uniquefolder')
  const uploads = countUploads(page)
  const folder = `trip-${Date.now()}`
  const dir = testInfo.outputPath(folder)
  await mkdir(`${dir}/day`, { recursive: true })
  await writeFile(`${dir}/x.txt`, 'x')
  await writeFile(`${dir}/y.txt`, 'y')
  await writeFile(`${dir}/day/z.txt`, 'z')

  await uploadFolder(page, dir)
  await expect(panel(page).getByText('Uploads complete')).toBeVisible({ timeout: 60_000 })
  await expect(item(page, folder)).toBeVisible({ timeout: 60_000 })
  expect(uploads.count).toBe(3)

  // Again, unchanged: no second folder, nothing sent.
  await uploadFolder(page, dir)
  await expect(panel(page).getByText('Uploads complete')).toBeVisible({ timeout: 60_000 })
  expect(uploads.count).toBe(3)
  await page.reload()
  await expect(item(page, folder)).toHaveCount(1, { timeout: 60_000 })
  await expect(item(page, `${folder} (2)`)).toHaveCount(0)

  // Two files changed: asked once, applied to the other.
  await writeFile(`${dir}/x.txt`, 'x, changed')
  await writeFile(`${dir}/y.txt`, 'y, changed')
  await uploadFolder(page, dir)
  await expect(conflict(page)).toBeVisible({ timeout: 60_000 })
  await conflict(page).getByRole('checkbox').check()
  await conflict(page).getByRole('button', { name: 'Keep both' }).click()
  await expect(panel(page).getByText('Uploads complete')).toBeVisible({ timeout: 60_000 })
  await expect(conflict(page)).toHaveCount(0)
  expect(uploads.count).toBe(5)

  await openItem(page, folder)
  for (const name of ['x.txt', 'y.txt', 'x (2).txt', 'y (2).txt', 'day']) await expect(item(page, name)).toBeVisible({ timeout: 60_000 })
  await expect(item(page, 'day (2)')).toHaveCount(0)
  await context.close()
})

test('a rename onto a taken name is refused, case aside; Turkish İ keeps its dot', async ({ browser }, testInfo) => {
  const { context, page } = await freshDrive(browser, 'uniquerename')
  const dir = testInfo.outputPath('names')
  await mkdir(dir, { recursive: true })
  await writeFile(`${dir}/notes.txt`, 'notes')
  await writeFile(`${dir}/istanbul.txt`, 'lower')
  await createFolder(page, 'Docs')
  await upload(page, `${dir}/notes.txt`, `${dir}/istanbul.txt`)
  await expect(item(page, 'istanbul.txt')).toBeVisible({ timeout: 60_000 })

  // Onto a folder's name, in other letter case.
  await itemAction(page, 'notes.txt', 'Rename')
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Name').fill('DOCS')
  await expect(dialog.getByText('Something here already has that name.')).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Rename', exact: true })).toBeDisabled()
  await dialog.getByLabel('Name').fill('ISTANBUL.TXT')
  await expect(dialog.getByText('Something here already has that name.')).toBeVisible()
  await dialog.getByRole('button', { name: 'Cancel' }).click()

  // Dotted capital İ is another letter: İstanbul.txt beside istanbul.txt.
  await renameItem(page, 'notes.txt', 'İstanbul.txt')
  await expect(item(page, 'istanbul.txt')).toBeVisible()
  // A case-only rename of an item's own name is fine.
  await renameItem(page, 'Docs', 'DOCS')
  await context.close()
})

test('items without hashes are filled in, and a restore into a taken name keeps both', async ({ browser }, testInfo) => {
  test.slow()
  const { context, page } = await freshDrive(browser, 'uniquefill')
  const dir = testInfo.outputPath('fill')
  await mkdir(`${dir}/second`, { recursive: true })
  await writeFile(`${dir}/plan.txt`, 'one')
  await writeFile(`${dir}/second/plan.txt`, 'two')

  // An older client: no name hashes, and it does not see what is there
  // (so this one does not stop it either). Nothing is filled in meanwhile.
  const hiddenFolders = new Set<string>()
  const hidden: string[] = []
  let hideFiles = false
  await context.route('**/name-hashes', (route) => route.abort())
  await context.route('**/api/collections', async (route) => {
    const request = route.request()
    if (request.method() === 'POST') {
      const body = request.postDataJSON() as Record<string, unknown>
      delete body.nameHash
      hiddenFolders.add(String(body.id))
      return route.continue({ postData: JSON.stringify(body) })
    }
    const response = await route.fetch()
    const rows = (await response.json()) as { id: string }[]
    // Only the first of each made here is hidden.
    await route.fulfill({ response, json: rows.filter((r) => !hidden.includes(r.id)) })
  })
  await context.route('**/api/collections/*/files', async (route) => {
    if (!hideFiles) return route.continue()
    await route.fulfill({ json: [] })
  })
  await context.route('**/api/uploads/', async (route) => {
    const headers = route.request().headers()
    const meta = headers['upload-metadata']
    if (route.request().method() !== 'POST' || !meta) return route.continue()
    const kept = meta.split(',').filter((pair) => !pair.startsWith('nameHash '))
    await route.continue({ headers: { ...headers, 'upload-metadata': kept.join(',') } })
  })

  await createFolder(page, 'Same')
  hidden.push(...hiddenFolders)
  await page.reload()
  await createFolder(page, 'Same')
  await upload(page, `${dir}/plan.txt`)
  await expect(item(page, 'plan.txt')).toBeVisible({ timeout: 60_000 })
  hideFiles = true
  await page.reload()
  await upload(page, `${dir}/second/plan.txt`)
  await expect(panel(page).getByText('In My files')).toHaveCount(1, { timeout: 60_000 })
  await context.unrouteAll({ behavior: 'wait' })

  // The owner opens the folder: both pairs are there, and the later of each
  // is renamed.
  await page.reload()
  await expect(item(page, 'Same (2)')).toBeVisible({ timeout: 60_000 })
  await expect(item(page, 'plan (2).txt')).toBeVisible({ timeout: 60_000 })
  await expect(item(page, 'Same')).toHaveCount(1)
  await expect(item(page, 'plan.txt')).toHaveCount(1)

  // A file restored after its name was taken comes back beside it.
  await itemAction(page, 'plan (2).txt', 'Move to trash')
  await expect(item(page, 'plan (2).txt')).toHaveCount(0, { timeout: 30_000 })
  await renameItem(page, 'plan.txt', 'plan (2).txt')
  await openSection(page, 'Trash')
  await itemAction(page, 'plan (2).txt', 'Restore')
  await expect(item(page, 'plan (2).txt')).toHaveCount(0, { timeout: 30_000 })
  await openSection(page, 'My files')
  await expect(item(page, 'plan (2).txt')).toBeVisible({ timeout: 60_000 })
  await expect(item(page, 'plan (3).txt')).toBeVisible({ timeout: 60_000 })
  await context.close()
})
