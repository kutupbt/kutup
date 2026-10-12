import { expect, test } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { addEntry, createVault, expectSaved, openPass } from '../fixtures/pass'

const PASSWORD = 'Deneme123*PassIconsAccount'
const VAULT_PASSWORD = 'kasa-parolası-çğ-152'
// A 1×1 PNG, so the run needs no outside website.
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64')

test('pass: entries show website icons through Kutup, or none, as the account chose', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('pass152', PASSWORD))
  const page = await context.newPage()
  const asked: string[] = []
  await page.route('**/api/pass/icon', async (route) => {
    asked.push(route.request().postDataJSON().domain)
    await route.fulfill({ status: 200, contentType: 'image/png', body: PNG })
  })
  await openPass(page)
  await expect(page.getByRole('combobox', { name: 'Website icons' })).toHaveText('Through Kutup (recommended)')
  await createVault(page, 'Kişisel', VAULT_PASSWORD)
  const vaultUrl = page.url()
  await addEntry(page, { title: 'GitHub', userName: 'ayse', url: 'https://github.com/login?return_to=/settings' })
  await addEntry(page, { title: 'Router', url: 'http://192.168.1.1/' })
  await expectSaved(page)

  // Through Kutup: only the host name is sent, and the icon is this tab's copy.
  const row = (title: string) => page.getByRole('list', { name: 'Entries' }).getByRole('button', { name: title })
  await expect(row('GitHub').locator('img')).toHaveAttribute('src', /^blob:/)
  await expect(row('Router').locator('img')).toHaveCount(0)
  await expect(row('Router')).toContainText('R')
  expect([...new Set(asked)]).toEqual(['github.com'])

  // Off, chosen for the account: another tab (as another device would)
  // shows first letters, asks nothing, and loads no outside image.
  await page.goto(appUrl('pass'))
  await page.getByRole('combobox', { name: 'Website icons' }).click()
  await expect(page.getByRole('option')).toHaveText(['Through Kutup (recommended)', 'Off'])
  await page.getByRole('option', { name: 'Off' }).click()
  await expect(page.getByText('Entries show their first letter')).toBeVisible()
  const other = await context.newPage()
  const otherAsked: string[] = []
  other.on('request', (request) => {
    if (request.url().includes('/api/pass/icon') || !request.url().includes('.localhost')) otherAsked.push(request.url())
  })
  await other.goto(vaultUrl)
  await expect(other.getByRole('heading', { name: 'Kişisel', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  const otherRow = other.getByRole('list', { name: 'Entries' }).getByRole('button', { name: 'GitHub' })
  await expect(otherRow).toContainText('G')
  await expect(otherRow.locator('img')).toHaveCount(0)
  expect(otherAsked).toEqual([])
  await context.close()
})
