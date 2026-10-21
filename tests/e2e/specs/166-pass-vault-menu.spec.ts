import { expect, test, type Page } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { createFolder } from '../fixtures/drive'
import { addEntry, createVault, expectSaved, openPass } from '../fixtures/pass'

const PASSWORD = 'Deneme123*PassVaultMenu'
const VAULT_PASSWORD = 'kasa-parolasi-166'

/** The vault's row in the list, and its menu. */
function vaultRow(page: Page, name: string) {
  return page.getByRole('list', { name: 'Vaults' }).getByRole('listitem').filter({ has: page.getByText(name, { exact: true }) })
}

async function vaultMenu(page: Page, name: string, item: string): Promise<void> {
  await page.getByRole('button', { name: `More for ${name}` }).click()
  await page.getByRole('menuitem', { name: item }).click()
}

// The vault list's menu (docs/plans/pass-parity.md, "Vault management from
// the vault list"): a locked vault renamed, downloaded, duplicated (its kept
// key kept for the copy), moved, deleted to Drive's trash; and a .kdbx
// uploaded back, checked against its key first.
test('pass: a vault is renamed while locked, downloaded, duplicated, moved, deleted, and uploaded back', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext({ acceptDownloads: true })
  await registerAccount(context, newAccount('pass166', PASSWORD))
  const page = await context.newPage()
  await page.goto(appUrl('drive'))
  await createFolder(page, 'Arşiv')
  await openPass(page)

  await createVault(page, 'Kilitli', VAULT_PASSWORD)
  await addEntry(page, { title: 'Banka', password: 'p0' })
  await expectSaved(page)
  await page.getByRole('button', { name: 'Vault actions' }).click()
  await page.getByRole('menuitem', { name: 'Lock vault' }).click()
  await openPass(page)

  // Renamed while locked: from the list, no unlock needed.
  await vaultMenu(page, 'Kilitli', 'Rename')
  const rename = page.getByRole('dialog', { name: 'Rename vault' })
  await rename.getByLabel('Vault name').fill('Yeni ad')
  await rename.getByRole('button', { name: 'Save' }).click()
  await expect(vaultRow(page, 'Yeni ad')).toBeVisible({ timeout: 30_000 })

  // Downloaded: said that the file is only as safe as its key.
  await vaultMenu(page, 'Yeni ad', 'Download .kdbx')
  const download = page.getByRole('dialog', { name: 'Download “Yeni ad”' })
  await expect(download).toContainText('only as safe as its key')
  const [file] = await Promise.all([page.waitForEvent('download'), download.getByTestId('vault-download-confirm').click()])
  expect(file.suggestedFilename()).toBe('Yeni ad.kdbx')
  const saved = test.info().outputPath('Yeni ad.kdbx')
  await file.saveAs(saved)

  // Duplicated: the copy shares the key, and opens with the sign-in too.
  await vaultMenu(page, 'Yeni ad', 'Duplicate')
  const duplicate = page.getByRole('dialog', { name: 'Duplicate “Yeni ad”' })
  await expect(duplicate).toContainText("master key")
  await duplicate.getByTestId('vault-duplicate-confirm').click()
  await expect(page.getByRole('heading', { name: 'Yeni ad (2)', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await expect(page.getByRole('list', { name: 'Entries' }).getByRole('button', { name: 'Banka' })).toBeVisible({ timeout: 60_000 })
  await openPass(page)

  // Moved: it keeps its key, wherever it goes.
  await vaultMenu(page, 'Yeni ad', 'Move to folder')
  const move = page.getByTestId('vault-move-dialog')
  await move.getByTestId('vault-move-folder').click()
  await page.getByRole('option', { name: 'Arşiv' }).click()
  await move.getByTestId('vault-move-confirm').click()
  await expect(vaultRow(page, 'Yeni ad')).toContainText('In Arşiv', { timeout: 30_000 })

  // The copy goes to Drive's trash.
  await vaultMenu(page, 'Yeni ad (2)', 'Delete')
  await page.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click()
  await expect(vaultRow(page, 'Yeni ad (2)')).toHaveCount(0, { timeout: 30_000 })

  // Uploaded back: not a .kdbx refused at once; the wrong password said
  // before anything is uploaded; the right one, and it opens.
  await page.getByTestId('vault-upload').click()
  const upload = page.getByTestId('vault-upload-dialog')
  await upload.getByTestId('vault-upload-file').setInputFiles({ name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('hello') })
  await expect(upload.getByTestId('vault-upload-error')).toContainText('Choose a KeePass file')
  await upload.getByTestId('vault-upload-file').setInputFiles(saved)
  await upload.getByTestId('vault-upload-password').fill('not the password')
  await upload.getByTestId('vault-upload-submit').click()
  await expect(upload.getByTestId('vault-upload-error')).toContainText("doesn't open this vault", { timeout: 60_000 })
  await upload.getByTestId('vault-upload-password').fill(VAULT_PASSWORD)
  await upload.getByTestId('vault-upload-submit').click()
  await expect(page.getByRole('heading', { name: 'Yeni ad', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await expect(page.getByRole('list', { name: 'Entries' }).getByRole('button', { name: 'Banka' })).toBeVisible({ timeout: 60_000 })
  // Its key is kept: it opens with the sign-in after a reload.
  await page.reload()
  await expect(page.getByRole('list', { name: 'Entries' }).getByRole('button', { name: 'Banka' })).toBeVisible({ timeout: 60_000 })
  await context.close()
})
