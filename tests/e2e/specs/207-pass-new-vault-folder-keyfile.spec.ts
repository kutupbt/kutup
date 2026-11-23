import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, test, type Page } from '../fixtures/test'
import { newAccount, registerAccount } from '../fixtures/apps'
import { expectSaved, openPass } from '../fixtures/pass'

const PASSWORD = 'Deneme123*PassNewVault207'
const VAULT_PASSWORD = 'derin-kasa-parolasi-207'

function vaultRow(page: Page, name: string) {
  return page.getByRole('list', { name: 'Vaults' }).getByRole('listitem').filter({ has: page.getByText(name, { exact: true }) })
}

// New vault's gaps (docs/roadmap.md, Pass): a folder made from the picker,
// a subfolder in it, and a key file generated there (KeePassXC's XML v2),
// downloaded and said saved before the vault is made; it then opens with
// that key file.
test('pass: a new vault goes in a subfolder made from the picker, with a generated key file, and reopens with it', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext({ acceptDownloads: true })
  await registerAccount(context, newAccount('pass207', PASSWORD))
  const page = await context.newPage()
  await openPass(page)

  await page.getByRole('button', { name: 'New vault' }).first().click()
  const dialog = page.getByRole('dialog', { name: 'New vault' })
  await dialog.getByLabel('Vault name').fill('Derin')
  const picker = dialog.getByRole('combobox', { name: 'Folder' })
  await expect(picker).toHaveText('My files')

  // A folder in My files, then one inside it: each made and chosen.
  for (const [folder, path] of [
    ['Dış', 'My files / Dış'],
    ['İç', 'My files / Dış / İç'],
  ]) {
    await dialog.getByRole('button', { name: 'New folder' }).click()
    const naming = page.getByRole('dialog', { name: 'New folder' })
    await naming.getByLabel('Name').fill(folder)
    await naming.getByRole('button', { name: 'Create folder' }).click()
    await expect(naming).toBeHidden({ timeout: 30_000 })
    await expect(picker).toHaveText(path)
  }
  // A name its siblings have is refused before it is sent.
  await picker.click()
  await page.getByRole('option', { name: 'My files', exact: true }).click()
  await dialog.getByRole('button', { name: 'New folder' }).click()
  let naming = page.getByRole('dialog', { name: 'New folder' })
  await naming.getByLabel('Name').fill('Dış')
  await expect(naming.getByText('Something here already has that name.')).toBeVisible()
  await naming.getByRole('button', { name: 'Cancel' }).click()
  await expect(naming).toBeHidden()
  await picker.click()
  await page.getByRole('option', { name: 'My files / Dış / İç' }).click()
  await expect(picker).toHaveText('My files / Dış / İç')

  // A password and a generated key file; not kept in the account.
  await dialog.getByRole('radio', { name: /A password I choose/ }).check()
  await dialog.getByLabel('Vault password', { exact: true }).fill(VAULT_PASSWORD)
  await dialog.getByLabel('Repeat the vault password').fill(VAULT_PASSWORD)
  await dialog.getByRole('checkbox', { name: 'Unlock with my Kutup sign-in' }).click()
  await dialog.getByRole('radio', { name: 'Generate a new key file' }).check()
  const create = dialog.getByRole('button', { name: 'Create vault' })
  await expect(create).toBeDisabled()
  await expect(dialog.getByTestId('new-vault-problem')).toHaveText('Generate the key file, download it, and say you saved it.')
  const [download] = await Promise.all([page.waitForEvent('download'), dialog.getByTestId('new-vault-key-generate').click()])
  expect(download.suggestedFilename()).toBe('Derin.keyx')
  // A key file is a secret: kept in a folder of its own, never with the test's
  // artifacts, and removed at the end.
  const keyDir = mkdtempSync(join(tmpdir(), 'kutup-e2e-keyfile-'))
  const keyFile = join(keyDir, 'Derin.keyx')
  await download.saveAs(keyFile)
  const xml = readFileSync(keyFile, 'utf8')
  expect(xml).toContain('<Version>2.0</Version>')
  expect(xml).toMatch(/<Data Hash="[0-9A-F]{8}">\s+([0-9A-F]{8} ){3}[0-9A-F]{8}\s+([0-9A-F]{8} ){3}[0-9A-F]{8}\s+<\/Data>/)
  // Not made before the key file is said to be saved, Enter or not.
  await dialog.getByLabel('Vault name').press('Enter')
  await expect(dialog).toBeVisible()
  await expect(create).toBeDisabled()
  await dialog.getByRole('checkbox', { name: /I saved Derin\.keyx/ }).click()
  await create.click()
  await expect(page.getByRole('heading', { name: 'Derin', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await expectSaved(page)

  // Reopened: the password alone does not open it; with the key file it does.
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Unlock Derin' })).toBeVisible({ timeout: 60_000 })
  const remember = page.getByRole('checkbox', { name: 'Unlock with my Kutup sign-in' })
  if (await remember.isChecked()) await remember.click()
  await page.getByLabel('Vault password', { exact: true }).fill(VAULT_PASSWORD)
  await page.getByRole('button', { name: 'Unlock', exact: true }).click()
  await expect(page.getByText('That password or key file does not open this vault.')).toBeVisible({ timeout: 30_000 })
  await page.locator('form input[type=file]').setInputFiles(keyFile)
  await page.getByRole('button', { name: 'Unlock', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Derin', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })

  // It is in the subfolder.
  await openPass(page)
  await expect(vaultRow(page, 'Derin')).toContainText('In İç', { timeout: 30_000 })
  await context.close()
  rmSync(keyDir, { recursive: true, force: true })
})
