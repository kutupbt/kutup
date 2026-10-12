import { expect, test } from '@playwright/test'
import { newAccount, registerAccount } from '../fixtures/apps'
import { addEntry, createVault, expectSaved, openEntry, openPass } from '../fixtures/pass'

const PASSWORD = 'Deneme123*PassOfflineAccount'

test('pass: edits made offline are kept on the device and saved when the connection is back, also after closing the tab', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('pass78', PASSWORD))
  const page = await context.newPage()
  await openPass(page)
  const vaultUrl = await createVault(page, 'Yolda', 'kasa-78-parola')

  // Offline: the edit is made and kept here.
  await context.setOffline(true)
  await addEntry(page, { title: 'Çevrimdışı kayıt', userName: 'uçakta', password: 'p-offline' })
  await expect(page.getByRole('status').filter({ hasText: 'Offline' })).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('Your changes are kept on this device')).toBeVisible()

  // Back online: saved.
  await context.setOffline(false)
  await expectSaved(page)
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Yolda', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await openEntry(page, 'Çevrimdışı kayıt')

  // Offline again, and the tab closed before the connection came back.
  await context.setOffline(true)
  await addEntry(page, { title: 'Kapanan sekme', userName: 'trende', password: 'p-closed' })
  await expect(page.getByRole('status').filter({ hasText: 'Offline' })).toBeVisible({ timeout: 30_000 })
  await page.close()
  await context.setOffline(false)

  // Opened again: the kept edit goes to Drive.
  const again = await context.newPage()
  await again.goto(vaultUrl)
  await expect(again.getByRole('heading', { name: 'Yolda', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await expectSaved(again)
  await openEntry(again, 'Kapanan sekme')
  await context.close()
})
