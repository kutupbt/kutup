import { expect, test } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { addEntry, createVault, expectSaved, openPass } from '../fixtures/pass'

const PASSWORD = 'Deneme123*PassIconsAccount'
const VAULT_PASSWORD = 'kasa-parolası-çğ-152'
// A 1×1 PNG, so the run needs no outside website.
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64')

test('pass: entries show website icons through Kutup, from the website, or not at all, as the account chose', async ({ browser }) => {
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
  await expectSaved(page)

  // Through Kutup: only the host name is sent, and the icon is this tab's copy.
  const row = (title: string) => page.getByRole('list', { name: 'Entries' }).getByRole('button', { name: title })
  await expect(row('GitHub').locator('img')).toHaveAttribute('src', /^blob:/)
  await expect(row('Router').locator('img')).toHaveCount(0)
  await expect(row('Router')).toContainText('R')
  expect([...new Set(asked)]).toEqual(['github.com'])

  // From the website: the browser asks it for /favicon.ico. The choice is the account's.
  await page.goto(appUrl('pass'))
  await page.getByRole('combobox', { name: 'Website icons' }).click()
  await page.getByRole('option', { name: 'Directly from the website' }).click()
  await expect(page.getByText('Your browser asks each website for its icon')).toBeVisible()
  // Another tab, as another device would: the image it asks the website
  // for is recorded (the run needs no outside website, and Playwright cannot
  // stand in for a /favicon.ico address).
  const other = await context.newPage()
  await other.addInitScript(() => {
    const asked: string[] = []
    Object.assign(window, { askedImages: asked })
    new MutationObserver((records) => {
      for (const record of records) {
        for (const node of record.addedNodes) {
          if (node instanceof HTMLElement) for (const img of [node, ...node.querySelectorAll('img')]) if (img instanceof HTMLImageElement) asked.push(`${img.src} ${img.referrerPolicy}`)
        }
      }
    }).observe(document, { childList: true, subtree: true })
  })
  await other.goto(vaultUrl)
  await expect(other.getByRole('heading', { name: 'Kişisel', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  const otherRow = other.getByRole('list', { name: 'Entries' }).getByRole('button', { name: 'GitHub' })
  await expect(otherRow).toBeVisible()
  await expect.poll(() => other.evaluate(() => (window as unknown as { askedImages: string[] }).askedImages)).toContain('https://github.com/favicon.ico no-referrer')

  // Off: first letters, and nothing is asked.
  await page.getByRole('combobox', { name: 'Website icons' }).click()
  await page.getByRole('option', { name: 'Off' }).click()
  await expect(page.getByText('Entries show their first letter')).toBeVisible()
  await other.reload()
  await expect(other.getByRole('heading', { name: 'Kişisel', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await expect(otherRow).toContainText('G')
  await expect(otherRow.locator('img')).toHaveCount(0)
  expect(await other.evaluate(() => (window as unknown as { askedImages: string[] }).askedImages)).toEqual([])
  await context.close()
})
