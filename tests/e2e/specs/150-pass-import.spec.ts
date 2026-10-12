import { expect, test } from '@playwright/test'
import { newAccount, registerAccount } from '../fixtures/apps'
import { createVault, expectSaved, openEntry, openPass, shownValue } from '../fixtures/pass'

const PASSWORD = 'Deneme123*PassImportAccount'
const VAULT_PASSWORD = 'kasa-parolası-çğ-150'

const BITWARDEN = [
  'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp',
  ',0,login,Banka,,,0,https://banka.example,ayşe,banka-parola-1,JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
  'İş,1,login,Sunucu,,"PIN: 1234",0,https://sunucu.example,root,sunucu-parola-2,',
  ',0,note,Kurtarma kodları,"aaaa\nbbbb",,0,,,,',
  ',0,card,Visa,,,0,,,,',
].join('\n')

test('pass: a Bitwarden export is read and shown first, then imported into a group of its own', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('pass150', PASSWORD))
  const page = await context.newPage()
  await openPass(page)
  await createVault(page, 'Kişisel', VAULT_PASSWORD)

  await page.getByRole('button', { name: 'Vault actions' }).click()
  await page.getByRole('menuitem', { name: 'Import from another app…' }).click()
  const dialog = page.getByRole('dialog', { name: 'Import passwords' })
  await expect(dialog.getByText(/unencrypted/)).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Import', exact: true })).toBeDisabled()

  // Not a password export: said so, nothing to import.
  let chooser = page.waitForEvent('filechooser')
  await dialog.getByRole('button', { name: 'Choose export file' }).click()
  await (await chooser).setFiles({ name: 'tablo.csv', mimeType: 'text/csv', buffer: Buffer.from('a,b,c\n1,2,3\n') })
  await expect(dialog.getByText(/do not look like a password export/)).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Import', exact: true })).toBeDisabled()

  // The Bitwarden export: recognised, previewed, the card left out.
  chooser = page.waitForEvent('filechooser')
  await dialog.getByRole('button', { name: 'Choose another file' }).click()
  await (await chooser).setFiles({ name: 'bitwarden_export.csv', mimeType: 'text/csv', buffer: Buffer.from(BITWARDEN) })
  await expect(dialog.getByText('3 entries found in a Bitwarden export.')).toBeVisible()
  const preview = dialog.getByRole('region', { name: 'What will be imported' })
  await expect(preview.getByRole('cell', { name: 'Sunucu' })).toBeVisible()
  await expect(preview.getByText('1 item will not be imported')).toBeVisible()
  await expect(preview.getByText(/Visa/)).toBeVisible()
  const into = dialog.getByLabel('Import into the group')
  await expect(into).toHaveValue(/^Imported from Bitwarden \(/)
  await into.fill('Bitwarden’dan')

  await dialog.getByRole('button', { name: 'Import 3 entries' }).click()
  await expect(dialog).toBeHidden()
  await expect(page.getByText('3 entries imported into Bitwarden’dan')).toBeVisible()
  await expectSaved(page)

  // Opened on the new group, with the folder as a group inside it.
  await expect(page.getByRole('list', { name: 'Entries' }).getByText('Banka')).toBeVisible()
  await openEntry(page, 'Banka')
  await expect(shownValue(page, 'Banka', 'User name')).toHaveText('ayşe')
  await expect(page.getByRole('article', { name: 'Banka' }).getByText(/^\d{3} \d{3}$/)).toBeVisible()

  // Kept after a reload.
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Kişisel', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await page.getByRole('button', { name: 'İş', exact: true }).click()
  await openEntry(page, 'Sunucu')
  await expect(shownValue(page, 'Sunucu', 'User name')).toHaveText('root')
  // A PIN is kept hidden, like a password.
  await expect(shownValue(page, 'Sunucu', 'PIN')).toHaveText('••••••••')
  await context.close()
})
