import { expect, test, type Page } from '@playwright/test'
import { appUrl, newAccount, openDrive, registerAccount, signIn } from '../fixtures/apps'

const PASSWORD = 'Deneme123*UiPreferencesPassword'
const PREFERENCES = /\/api\/account\/ui-preferences$/

function saved(page: Page) {
  return page.waitForResponse((r) => r.request().method() === 'PUT' && PREFERENCES.test(new URL(r.url()).pathname))
}

test('theme and language chosen in one app follow the account into the others', async ({ browser }) => {
  test.slow()
  const account = newAccount('uiprefs', PASSWORD)
  const context = await browser.newContext({ colorScheme: 'light' })
  await registerAccount(context, account)

  // Drive: dark, then Turkish, from the account menu.
  const drive = await openDrive(context)
  await expect(drive.locator('html')).toHaveAttribute('lang', 'en')
  await drive.getByRole('button', { name: 'Account menu' }).click()
  let put = saved(drive)
  await drive.getByRole('button', { name: 'Dark theme' }).click()
  expect((await put).ok()).toBe(true)
  await expect(drive.locator('html')).toHaveClass(/\bdark\b/)
  put = saved(drive)
  await drive.getByRole('button', { name: 'Switch language' }).click()
  expect((await put).ok()).toBe(true)
  await expect(drive.locator('html')).toHaveAttribute('lang', 'tr')

  // Office has never been opened in this browser: it takes both from the account.
  const office = await context.newPage()
  await office.goto(appUrl('office'))
  await expect(office.locator('html')).toHaveClass(/\bdark\b/, { timeout: 120_000 })
  await expect(office.locator('html')).toHaveAttribute('lang', 'tr')

  // Back to light from Office; Drive, holding dark itself, follows the account.
  await office.getByRole('button', { name: 'Hesap menüsü' }).click()
  put = saved(office)
  await office.getByRole('button', { name: 'Açık tema' }).click()
  expect((await put).ok()).toBe(true)
  await drive.reload()
  await expect(drive.locator('html')).not.toHaveClass(/\bdark\b/, { timeout: 60_000 })
  await expect(drive.locator('html')).toHaveAttribute('lang', 'tr')

  // Another device (a fresh browser) gets them on sign-in too.
  const elsewhere = await browser.newContext({ colorScheme: 'dark' })
  await signIn(elsewhere, account)
  // (Turkish there from the start, so no English-text helpers.)
  const there = await elsewhere.newPage()
  await there.goto(appUrl('drive'))
  await expect(there.locator('html')).toHaveAttribute('lang', 'tr', { timeout: 120_000 })
  await expect(there.locator('html')).not.toHaveClass(/\bdark\b/)

  await context.close()
  await elsewhere.close()
})
