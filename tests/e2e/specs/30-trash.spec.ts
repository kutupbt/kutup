import { expect, test, type Page } from '../fixtures/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { backFromEditor, createFolder, createNote, item, itemAction, openItem, openSection, renameItem } from '../fixtures/drive'

const PASSWORD = 'Deneme123*TrashPassword'

async function trashItem(page: Page, name: string) {
  await itemAction(page, name, 'Move to trash')
  await expect(item(page, name)).toHaveCount(0, { timeout: 30_000 })
}

test('file: move to trash, restore, then delete forever', async ({ browser }) => {
  const context = await browser.newContext()
  await registerAccount(context, newAccount('trashfile', PASSWORD))
  const page = await openDrive(context)
  const note = await createNote(page)
  await backFromEditor(page)
  const name = `trash-file-${Date.now()}.md`
  await renameItem(page, note, name)

  await trashItem(page, name)
  await openSection(page, 'Trash')
  await expect(item(page, name)).toBeVisible({ timeout: 30_000 })
  await itemAction(page, name, 'Restore')
  await expect(item(page, name)).toHaveCount(0, { timeout: 30_000 })
  await openSection(page, 'My files')
  await expect(item(page, name)).toBeVisible({ timeout: 30_000 })

  await trashItem(page, name)
  await openSection(page, 'Trash')
  await itemAction(page, name, 'Delete forever')
  await page.getByRole('alertdialog').getByRole('button', { name: 'Delete forever', exact: true }).click()
  await expect(item(page, name)).toHaveCount(0, { timeout: 30_000 })

  await page.reload()
  try {
    await expect(page.getByText('Trash is empty')).toBeVisible({ timeout: 60_000 })
  } catch (error) {
    // Where the reloaded page stood, in numbers and fixed words only (no
    // names), so the sanitized reporter passes it with
    // KUTUP_E2E_DRIVE_DIAGNOSTICS=1: its path, the rows it lists, whether
    // the deleted file is among them, and any alert or reload notice.
    const path = new URL(page.url()).pathname.replace(/[0-9a-f-]{36}/g, ':id')
    const rows = await page.getByRole('row').count()
    const stillListed = await item(page, name).count()
    const alerts = await page.getByRole('alert').count()
    const reloadNotice = await page.getByRole('button', { name: /^Reload$/ }).count()
    const listed = await page.getByRole('main').count()
    console.log(
      `DRIVE DIAGNOSTIC 30 after-reload path=${path} main=${listed} rows=${rows} deletedStillListed=${stillListed} alerts=${alerts} reloadButtons=${reloadNotice}`,
    )
    throw error
  }
  await context.close()
})

test('folder: trashing keeps one entry; restoring brings its file back', async ({ browser }) => {
  const context = await browser.newContext()
  await registerAccount(context, newAccount('trashfolder', PASSWORD))
  const page = await openDrive(context)
  const folder = `trash-folder-${Date.now()}`
  await createFolder(page, folder)
  await openItem(page, folder)
  await expect(page.getByRole('navigation', { name: 'Breadcrumb' })).toContainText(folder, { timeout: 30_000 })
  // A selection made in the parent does not follow into the folder.
  await expect(page.getByText(/^\d+ selected$/)).toHaveCount(0)
  const note = await createNote(page)
  await backFromEditor(page)
  await expect(item(page, note)).toBeVisible()

  await openSection(page, 'My files')
  await trashItem(page, folder)
  await openSection(page, 'Trash')
  await expect(item(page, folder)).toBeVisible({ timeout: 30_000 })
  // One entry for the folder; its contents are not listed separately.
  await expect(item(page, note)).toHaveCount(0)

  await itemAction(page, folder, 'Restore')
  await openSection(page, 'My files')
  await openItem(page, folder)
  await expect(item(page, note)).toBeVisible({ timeout: 30_000 })
  await context.close()
})
