import { expect, test } from '../fixtures/test'
import { appUrl, newAccount, openDrive, registerAccount } from '../fixtures/apps'

// Drive's keys (docs/roadmap.md, "Keyboard shortcuts in every app"): ? lists
// them, / goes to search, and the account's switch (Drive's Settings, or the
// list) turns those two off; moving through the list still works.

const PASSWORD = 'Deneme123*DriveShortcutsPassword'

test('drive shortcuts: ? lists them, / searches, and the switch turns them off', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('drvkeys', PASSWORD))
  const page = await openDrive(context)
  const search = page.getByRole('searchbox').first()
  await expect(search).toBeVisible({ timeout: 120_000 })

  await page.locator('body').click({ position: { x: 5, y: 5 } })
  await page.keyboard.press('?')
  const dialog = page.getByTestId('shortcuts-dialog')
  await expect(dialog).toBeVisible()
  await expect(dialog).toContainText('Quick look')
  await page.keyboard.press('Escape')
  await expect(dialog).toBeHidden()

  await page.keyboard.press('/')
  await expect(search).toBeFocused()
  await search.blur()

  // Off from Drive's Settings: / and ? do nothing.
  await page.goto(appUrl('drive', '/settings'))
  const saved = page.waitForRequest((sent) => sent.method() === 'PUT' && new URL(sent.url()).pathname === '/api/v1/account/ui-preferences')
  await page.getByTestId('shortcuts-enabled').click()
  await saved
  await page.goBack()
  await expect(search).toBeVisible({ timeout: 60_000 })
  await page.locator('body').click({ position: { x: 5, y: 5 } })
  await page.keyboard.press('/')
  await expect(search).not.toBeFocused()
  await page.keyboard.press('?')
  await expect(dialog).toBeHidden()
  await context.close()
})
