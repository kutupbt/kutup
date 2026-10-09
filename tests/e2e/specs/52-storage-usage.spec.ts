import { expect, test } from '@playwright/test'
import { backFromEditor, createNote, itemAction } from '../fixtures/drive'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'

const PASSWORD = 'Deneme123*StorageUsagePassword'
const BIG_BYTES = 11 * 1000 * 1000

test('the storage summary, the Storage page and freeing space', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('storage', PASSWORD))

  // One large file to find, and a note in the trash to empty.
  const drive = await openDrive(context)
  const big = `big-${Date.now()}.bin`
  await drive.getByRole('button', { name: 'New' }).first().click()
  const [chooser] = await Promise.all([
    drive.waitForEvent('filechooser'),
    drive.getByRole('menuitem', { name: 'Upload files' }).click(),
  ])
  await chooser.setFiles({ name: big, mimeType: 'application/octet-stream', buffer: Buffer.alloc(BIG_BYTES, 7) })
  await expect(drive.getByText('Uploads complete')).toBeVisible({ timeout: 120_000 })
  await expect(drive.getByText(big, { exact: true }).first()).toBeVisible()
  const note = await createNote(drive)
  await backFromEditor(drive)
  await itemAction(drive, note, 'Move to trash')

  // The sidebar meter opens a summary with the way to the Storage page.
  await drive.reload()
  await drive.getByRole('button', { name: /^Storage: .* used/ }).click()
  const summary = drive.getByRole('dialog')
  await expect(summary.getByText('Shared by Drive, Photos, Office, Maps and Chat.')).toBeVisible({ timeout: 30_000 })
  await expect(summary.getByRole('link', { name: 'Free up space' })).toHaveAttribute('href', /\/settings\/storage\?cleanup=1$/)
  await summary.getByRole('link', { name: 'Details' }).click()
  await drive.waitForURL(/\/settings\/storage$/, { timeout: 60_000 })

  // What fills the pool, largest first, with the kinds this browser decrypted.
  await expect(drive.getByRole('heading', { name: 'Storage', level: 1 })).toBeVisible({ timeout: 120_000 })
  const breakdown = drive.getByRole('list', { name: 'What fills your storage' })
  await expect(breakdown.getByRole('listitem').first()).toContainText('Other files', { timeout: 60_000 })
  await expect(breakdown).toContainText('Trash')
  await expect(breakdown).toContainText('Free')
  await expect(drive.getByText('Other files · 1 file').last()).toBeVisible()

  // Free up space: empty the trash, then send the large file to it.
  await drive.getByRole('button', { name: 'Free up space' }).click()
  await expect(drive).toHaveURL(/cleanup=1/)
  const cleanup = drive.getByRole('dialog', { name: 'Free up space' })
  await expect(cleanup.getByText('1 file waiting to be deleted.', { exact: false })).toBeVisible()
  await cleanup.getByRole('button', { name: 'Empty trash' }).click()
  const confirm = drive.getByRole('alertdialog', { name: 'Empty the trash?' })
  await confirm.getByRole('button', { name: 'Empty trash' }).click()
  await expect(drive.getByText('Trash emptied')).toBeVisible({ timeout: 30_000 })
  await expect(cleanup.getByText('The trash is empty.')).toBeVisible({ timeout: 30_000 })

  const large = cleanup.getByRole('list', { name: 'Large files' })
  await expect(large).toContainText(big, { timeout: 60_000 })
  await large.getByRole('checkbox', { name: `Select ${big}` }).check()
  await cleanup.getByRole('button', { name: /^Move 1 file to trash/ }).click()
  await expect(drive.getByText('1 file moved to trash')).toBeVisible({ timeout: 30_000 })
  await expect(cleanup.getByText('You have no large files.')).toBeVisible({ timeout: 30_000 })
  await expect(cleanup.getByText('1 file waiting to be deleted.', { exact: false })).toBeVisible({ timeout: 30_000 })
  await drive.keyboard.press('Escape')
  await expect(drive).not.toHaveURL(/cleanup=1/)

  // The account page shows the same single figure and links here.
  await drive.getByRole('link', { name: 'Account', exact: true }).click()
  await drive.waitForURL(/\/settings\/account$/)
  const main = drive.getByRole('main')
  await expect(main.getByText('Storage', { exact: true })).toBeVisible()
  await expect(main.getByRole('link', { name: / of / })).toHaveAttribute('href', '/settings/storage')
  await expect(main.getByText('Chat storage')).toHaveCount(0)
  await context.close()
})
