import { expect, test } from '@playwright/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { addEntry, createVault, editEntry, expectSaved, openEntry, openPass, shownValue } from '../fixtures/pass'

const PASSWORD = 'Deneme123*PassVaultAccount'
const VAULT_PASSWORD = 'kasa-parolası-çğ-76'

test('pass: a vault in Drive, entries with history, one-time codes and attachments, opened again with the sign-in', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] })
  await registerAccount(context, newAccount('pass76', PASSWORD))
  const page = await context.newPage()
  await openPass(page)
  await expect(page.getByText('No vaults yet')).toBeVisible()

  await createVault(page, 'Kişisel', VAULT_PASSWORD)
  await addEntry(page, {
    title: 'Banka',
    userName: 'ayse',
    password: 'ilk-parola-1',
    url: 'https://banka.example',
    otp: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
  })
  await expectSaved(page)
  const banka = page.getByRole('article', { name: 'Banka' })
  await expect(shownValue(page, 'Banka', 'User name')).toHaveText('ayse')
  // The one-time code from the secret, counting down.
  await expect(banka.getByText(/^\d{3} \d{3}$/)).toBeVisible()
  await expect(banka.getByText(/\d+ seconds?/)).toBeVisible()
  // The password is hidden until shown, and copies.
  await expect(banka.getByText('ilk-parola-1')).toBeHidden()
  await banka.getByRole('button', { name: 'Show password' }).click()
  await expect(banka.getByText('ilk-parola-1')).toBeVisible()
  await banka.getByRole('button', { name: 'Copy Password' }).click()
  await expect(page.getByText('Password copied')).toBeVisible()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('ilk-parola-1')

  // An edit keeps the previous state in the history.
  await editEntry(page, 'Banka', { password: 'yeni-parola-2' })
  await expectSaved(page)
  await banka.getByRole('button', { name: '1 earlier version' }).click()
  const history = page.getByRole('dialog', { name: 'Earlier versions' })
  await history.getByRole('button', { name: 'Show' }).click()
  await expect(history.getByText('ilk-parola-1')).toBeVisible()
  await history.getByRole('button', { name: 'Close' }).click()

  // An attachment.
  const chooser = page.waitForEvent('filechooser')
  await banka.getByRole('button', { name: 'Attach file' }).click()
  await (await chooser).setFiles({ name: 'kurtarma-kodlari.txt', mimeType: 'text/plain', buffer: Buffer.from('1111-2222\n3333-4444\n') })
  await expect(banka.getByText('kurtarma-kodlari.txt')).toBeVisible()
  await expectSaved(page)

  // A group, and an entry in it.
  await page.getByRole('button', { name: 'Actions for Kişisel' }).click()
  await page.getByRole('menuitem', { name: 'New group inside' }).click()
  const groupDialog = page.getByRole('dialog', { name: 'New group' })
  await groupDialog.getByLabel('Group name').fill('İş')
  await groupDialog.getByRole('button', { name: 'Save' }).click()
  await addEntry(page, { title: 'Sunucu', userName: 'root', password: 'sunucu-parola' })
  await expectSaved(page)

  // Reloaded: the vault opens with the Kutup sign-in, everything there.
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Kişisel', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  // The page reopens on the group it showed; every entry is a click away.
  await page.getByRole('button', { name: 'All entries' }).click()
  await openEntry(page, 'Banka')
  await expect(shownValue(page, 'Banka', 'User name')).toHaveText('ayse')
  await expect(page.getByRole('article', { name: 'Banka' }).getByText('kurtarma-kodlari.txt')).toBeVisible()
  await page.getByRole('button', { name: 'İş', exact: true }).click()
  await expect(page.getByRole('list', { name: 'Entries' }).getByText('Sunucu')).toBeVisible()

  // Deleting goes to the recycle bin first.
  await openEntry(page, 'Sunucu')
  await page.getByRole('article', { name: 'Sunucu' }).getByRole('button', { name: 'Delete' }).click()
  await page.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click()
  await expectSaved(page)
  await page.getByRole('button', { name: 'Recycle bin' }).click()
  await expect(page.getByRole('list', { name: 'Entries' }).getByText('Sunucu')).toBeVisible()

  // On a phone: the list, then the entry on its own, and back.
  await page.setViewportSize({ width: 390, height: 844 })
  await page.getByRole('combobox', { name: 'Groups' }).click()
  await page.getByRole('option', { name: 'All entries' }).click()
  await page.getByRole('list', { name: 'Entries' }).getByRole('button', { name: /Banka/ }).click()
  await expect(page.getByRole('article', { name: 'Banka' })).toBeVisible()
  await expect(page.getByRole('list', { name: 'Entries' })).toBeHidden()
  await page.getByRole('button', { name: 'Back' }).click()
  await expect(page.getByRole('list', { name: 'Entries' })).toBeVisible()
  const width = await page.evaluate(() => document.documentElement.scrollWidth)
  expect(width).toBeLessThanOrEqual(390)
  await page.setViewportSize({ width: 1280, height: 800 })

  // The vault is a KeePass file in Drive.
  const drive = await openDrive(context)
  await expect(drive.getByText('Kişisel.kdbx')).toBeVisible({ timeout: 60_000 })
  await context.close()
})
