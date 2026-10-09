import { expect, test } from '@playwright/test'
import { backFromEditor, createNote } from '../fixtures/drive'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'

const PASSWORD = 'Deneme123*StorageUsagePassword'

test("Drive's storage meter opens the account's one storage pool, by app and by file type", async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('storage', PASSWORD))

  const drive = await openDrive(context)
  await createNote(drive)
  await backFromEditor(drive)

  // The meter in Drive's sidebar links to Account → Settings → Storage.
  const meter = drive.getByRole('link', { name: /used/ }).filter({ has: drive.getByRole('meter') })
  await expect(meter).toHaveAttribute('href', /\/settings\/storage$/)
  await meter.click()
  await drive.waitForURL(/\/settings\/storage$/, { timeout: 60_000 })

  await expect(drive.getByRole('heading', { name: 'Storage', level: 1 })).toBeVisible({ timeout: 120_000 })
  // One pool: Drive and Chat both appear in the legend; there is no separate Chat quota.
  await expect(drive.getByRole('meter', { name: 'Storage' })).toBeVisible()
  await expect(drive.getByRole('heading', { name: 'Drive' })).toBeVisible()
  await expect(drive.getByRole('heading', { name: 'Chat' })).toBeVisible()
  await expect(drive.getByText('1 file', { exact: true })).toBeVisible()
  await expect(drive.getByText('Message history backup')).toBeVisible()
  // The file types come from the names this browser decrypted.
  await expect(drive.getByText('Notes · 1 file')).toBeVisible({ timeout: 60_000 })

  // The account page shows the same single figure and links back here.
  await drive.getByRole('link', { name: 'Account', exact: true }).click()
  await drive.waitForURL(/\/settings\/account$/)
  const main = drive.getByRole('main')
  await expect(main.getByText('Storage', { exact: true })).toBeVisible()
  await expect(main.getByRole('link', { name: / of / })).toHaveAttribute('href', '/settings/storage')
  await expect(main.getByText('Chat storage')).toHaveCount(0)
  await context.close()
})
