import { createHash } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import { expect, test, type Page } from '../fixtures/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { createFolder, item, itemAction, openItem } from '../fixtures/drive'

// An item's details (Proton Drive's "Details"): a file's name, location,
// creator, dates, type, sizes, versions, sharing and the check of its
// signature; a folder's the same where they apply.

const PASSWORD = 'Deneme123*DriveDetailsSpec'

function svg(width: number): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20"><rect width="${width}" height="20" fill="#37a"/></svg>\n`
}

async function upload(page: Page, path: string) {
  await page.getByRole('button', { name: 'New' }).first().click()
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), page.getByRole('menuitem', { name: 'Upload files' }).click()])
  await chooser.setFiles(path)
}

const details = (page: Page) => page.getByTestId('details')
const field = (page: Page, id: string) => details(page).getByTestId(`details-${id}`)

test('a file’s and a folder’s details say what Kutup knows of them', async ({ browser }, testInfo) => {
  test.slow()
  const context = await browser.newContext()
  const alice = newAccount('details', PASSWORD)
  await registerAccount(context, alice)
  const page = await openDrive(context)
  const dir = testInfo.outputPath('files')
  await mkdir(`${dir}/new`, { recursive: true })
  const first = svg(40)
  await writeFile(`${dir}/chart.svg`, first)
  await writeFile(`${dir}/new/chart.svg`, svg(90))

  await createFolder(page, 'Reports')
  await openItem(page, 'Reports')
  await upload(page, `${dir}/chart.svg`)
  await expect(item(page, 'chart.svg')).toBeVisible({ timeout: 60_000 })

  // The file: where it is, who made it, what it is, and its signature checked.
  await itemAction(page, 'chart.svg', 'Details')
  await expect(details(page).getByRole('heading', { name: 'File details' })).toBeVisible()
  await expect(field(page, 'name')).toHaveText('chart.svg')
  await expect(field(page, 'location')).toHaveText('My files › Reports')
  await expect(field(page, 'created-by')).toContainText(alice.username, { timeout: 30_000 })
  await expect(field(page, 'last-uploaded-by')).toHaveCount(0)
  await expect(field(page, 'type')).toHaveText('Image')
  await expect(field(page, 'media-type')).toHaveText('image/svg+xml')
  await expect(field(page, 'versions')).toHaveText('1', { timeout: 30_000 })
  await expect(field(page, 'size')).toBeVisible()
  await expect(field(page, 'shared')).toHaveText('No', { timeout: 30_000 })
  await expect(details(page).getByTestId('details-signature')).toHaveAttribute('data-verdict', 'verified', { timeout: 30_000 })
  await expect(details(page).getByTestId('details-signature')).toContainText('Digital signature verified')
  // The advanced part: exact sizes and the upload's digest.
  await details(page).getByTestId('details-advanced').click()
  await expect(field(page, 'original-size-bytes')).toHaveText(String(Buffer.byteLength(first)))
  await expect(field(page, 'sha256')).toHaveText(createHash('sha256').update(first).digest('hex'))
  await page.keyboard.press('Escape')
  await expect(details(page)).toHaveCount(0)

  // A new version: counted, its signature checked, its own size.
  await upload(page, `${dir}/new/chart.svg`)
  await page.getByRole('dialog').filter({ hasText: 'is already here' }).getByRole('button', { name: 'Replace' }).click()
  await expect(page.getByRole('region', { name: 'Uploads' }).getByText('Uploads complete')).toBeVisible({ timeout: 60_000 })
  await itemAction(page, 'chart.svg', 'Details')
  await expect(field(page, 'versions')).toHaveText('2', { timeout: 30_000 })
  await expect(details(page).getByTestId('details-signature')).toHaveAttribute('data-verdict', 'verified', { timeout: 30_000 })
  await details(page).getByTestId('details-advanced').click()
  await expect(field(page, 'original-size-bytes')).toHaveText(String(Buffer.byteLength(svg(90))))
  await details(page).getByRole('button', { name: 'Close' }).last().click()
  await expect(details(page)).toHaveCount(0)

  // The folder, once it has a public link.
  await page.getByRole('link', { name: 'My files', exact: true }).first().click()
  await expect(item(page, 'Reports')).toBeVisible({ timeout: 30_000 })
  await itemAction(page, 'Reports', 'Get public link')
  const link = page.getByRole('dialog')
  await expect(link.getByRole('textbox')).toHaveValue(/#v1\./, { timeout: 30_000 })
  await page.keyboard.press('Escape')
  await expect(link).toHaveCount(0)
  await itemAction(page, 'Reports', 'Details')
  await expect(details(page).getByRole('heading', { name: 'Folder details' })).toBeVisible()
  await expect(field(page, 'name')).toHaveText('Reports')
  await expect(field(page, 'location')).toHaveText('My files')
  await expect(field(page, 'type')).toHaveText('Folder')
  await expect(field(page, 'shared')).toHaveText('1 public link', { timeout: 30_000 })
  await expect(details(page).getByTestId('details-signature')).toHaveCount(0)
  await context.close()
})
