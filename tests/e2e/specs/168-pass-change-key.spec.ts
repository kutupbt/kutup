import { readFileSync } from 'node:fs'
import { expect, test, type Page } from '@playwright/test'
import { newAccount, registerAccount } from '../fixtures/apps'
import { addEntry, createVault, expectSaved, openPass } from '../fixtures/pass'

const PASSWORD = 'Deneme123*PassChangeKey'
const FIRST = 'ilk-kasa-parolasi-168'
const SECOND = 'ikinci-kasa-parolasi-168'
const THIRD = 'ucuncu-kasa-parolasi-168'

const heading = (page: Page) => page.getByRole('heading', { name: 'Anahtar', exact: true, level: 1 })
const banka = (page: Page) => page.getByRole('list', { name: 'Entries' }).getByRole('button', { name: /Banka/ })

async function openDialog(page: Page) {
  await page.getByRole('button', { name: 'Vault actions' }).click()
  await page.getByRole('menuitem', { name: 'Change vault key…' }).click()
  const dialog = page.getByTestId('change-key-dialog')
  await expect(dialog.getByTestId('change-key-now')).toBeVisible()
  return dialog
}

async function changed(page: Page) {
  await expect(page.getByText("The vault's key was changed")).toBeVisible({ timeout: 60_000 })
  await expectSaved(page)
}

/** After a reload, the vault asks for its key: wrong ones refused, then opened (not kept). */
async function unlockAfterReload(page: Page, wrong: { password?: string; keyFile?: string }, right: { password?: string; keyFile?: string }) {
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Unlock Anahtar' })).toBeVisible({ timeout: 60_000 })
  const remember = page.getByRole('checkbox', { name: 'Unlock with my Kutup sign-in' })
  if (await remember.isChecked()) await remember.click()
  const fill = async (key: { password?: string; keyFile?: string }) => {
    await page.getByLabel('Vault password', { exact: true }).fill(key.password ?? '')
    const remove = page.getByRole('button', { name: 'Remove key file' })
    if (await remove.isVisible()) await remove.click()
    if (key.keyFile) await page.locator('form input[type=file]').setInputFiles(key.keyFile)
    await page.getByRole('button', { name: 'Unlock', exact: true }).click()
  }
  await fill(wrong)
  await expect(page.getByText('That password or key file does not open this vault.')).toBeVisible({ timeout: 30_000 })
  await fill(right)
  await expect(banka(page)).toBeVisible({ timeout: 60_000 })
}

// Changing a vault's key (docs/plans/pass-parity.md, "Change the vault's
// key"): a new password; a generated KeePassXC key file, downloaded and said
// saved before anything changes; the password removed; never no key at all;
// kept in the account again; the earlier versions deleted by the owner.
test("pass: a vault's key is changed: password, a generated key file, the password removed, re-kept, earlier versions deleted", async ({ browser }) => {
  test.slow()
  const context = await browser.newContext({ acceptDownloads: true })
  await registerAccount(context, newAccount('pass168', PASSWORD))
  const page = await context.newPage()
  await openPass(page)
  await createVault(page, 'Anahtar', FIRST, false)
  await addEntry(page, { title: 'Banka', password: 'p0' })
  await expectSaved(page)

  // A new password: the old one no longer opens it.
  let dialog = await openDialog(page)
  await expect(dialog.getByTestId('change-key-now')).toHaveText('Now: a password.')
  await expect(dialog).toContainText('earlier versions of this vault')
  await expect(dialog).toContainText("can't be revoked")
  await dialog.getByRole('radio', { name: 'A new password' }).check()
  await dialog.getByLabel('New password', { exact: true }).fill(SECOND)
  await dialog.getByLabel('Repeat the new password').fill(SECOND)
  await dialog.getByTestId('change-key-submit').click()
  await changed(page)
  await unlockAfterReload(page, { password: FIRST }, { password: SECOND })

  // A generated key file: downloaded, KeePassXC's XML v2; nothing changes
  // before it is said to be saved, Enter or not.
  dialog = await openDialog(page)
  await dialog.getByRole('radio', { name: 'Generate a new key file' }).check()
  await expect(dialog.getByTestId('change-key-submit')).toBeDisabled()
  const [file] = await Promise.all([page.waitForEvent('download'), dialog.getByTestId('change-key-generate').click()])
  expect(file.suggestedFilename()).toBe('Anahtar.keyx')
  const keyFile = test.info().outputPath('Anahtar.keyx')
  await file.saveAs(keyFile)
  const xml = readFileSync(keyFile, 'utf8')
  expect(xml).toContain('<Version>2.0</Version>')
  expect(xml).toMatch(/<Data Hash="[0-9A-F]{8}">\s+([0-9A-F]{8} ){3}[0-9A-F]{8}\s+([0-9A-F]{8} ){3}[0-9A-F]{8}\s+<\/Data>/)
  await dialog.getByRole('radio', { name: 'Generate a new key file' }).press('Enter')
  await expect(dialog).toBeVisible()
  await expect(dialog.getByTestId('change-key-submit')).toBeDisabled()
  await dialog.getByRole('checkbox', { name: /I saved Anahtar\.keyx/ }).click()
  await dialog.getByTestId('change-key-submit').click()
  await changed(page)
  await unlockAfterReload(page, { password: SECOND }, { password: SECOND, keyFile })

  // Never no key at all.
  dialog = await openDialog(page)
  await expect(dialog.getByTestId('change-key-now')).toHaveText('Now: a password and a key file.')
  await dialog.getByRole('radio', { name: 'No password' }).check()
  await dialog.getByRole('radio', { name: 'No key file' }).check()
  await expect(dialog.getByTestId('change-key-problem')).toHaveText('A vault needs a password, a key file, or both.')
  await expect(dialog.getByTestId('change-key-submit')).toBeDisabled()

  // The password removed, the key file kept; kept in the account this time.
  await dialog.getByRole('radio', { name: 'Keep the key file' }).check()
  await dialog.getByRole('checkbox', { name: 'Unlock with my Kutup sign-in' }).click()
  await dialog.getByTestId('change-key-submit').click()
  await changed(page)
  await page.reload()
  await expect(banka(page)).toBeVisible({ timeout: 60_000 })

  // A new password over the kept key, and the earlier versions deleted, asked first.
  dialog = await openDialog(page)
  await expect(dialog.getByTestId('change-key-now')).toHaveText('Now: a key file.')
  await dialog.getByRole('radio', { name: 'A new password' }).check()
  await dialog.getByLabel('New password', { exact: true }).fill(THIRD)
  await dialog.getByLabel('Repeat the new password').fill(THIRD)
  await dialog.getByRole('checkbox', { name: "Also delete this vault's earlier versions" }).click()
  await dialog.getByTestId('change-key-submit').click()
  const confirm = page.getByRole('alertdialog', { name: 'Change the key and delete the earlier versions?' })
  await expect(confirm).toContainText("Deleted versions can't be brought back.")
  await confirm.getByRole('button', { name: 'Change key and delete versions' }).click()
  await changed(page)
  await expect(page.getByText(/could not be deleted/)).toHaveCount(0)
  // Kept again: opens with the sign-in; and with the new password and the key file.
  await page.reload()
  await expect(banka(page)).toBeVisible({ timeout: 60_000 })
  await expect(heading(page)).toBeVisible()
  await context.close()
})
