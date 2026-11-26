import { expect, test } from '../fixtures/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Keyboard shortcuts (docs/roadmap.md, "Keyboard shortcuts in every app";
// Proton's calendar shortcuts plus D W M): the views by letter and number, ?
// for the list, and the account's switch, which turns them off in every app
// and on every device and survives a reload.

const PASSWORD = 'Deneme123*CalendarShortcutsPassword'

test('calendar shortcuts change the view, list themselves, and turn off for the account', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext({ viewport: { width: 1400, height: 1000 } })
  await context.addInitScript(() => {
    localStorage.setItem('kutup.calendar.notificationBannerDismissed', '1')
  })
  await registerAccount(context, newAccount('calkeys', PASSWORD))
  const page = await context.newPage()
  await page.goto(appUrl('calendar', '/?view=week&date=2026-10-29'))
  await expect(page.getByTestId('calendar-list-item').first()).toBeVisible({ timeout: 120_000 })
  const view = () => new URL(page.url()).searchParams.get('view')

  for (const [key, expected] of [
    ['d', 'day'],
    ['m', 'month'],
    ['w', 'week'],
    ['1', 'day'],
    ['3', 'month'],
    ['2', 'week'],
  ] as const) {
    await page.keyboard.press(key)
    await expect.poll(view).toBe(expected)
  }

  // ? lists them, with the switch.
  await page.keyboard.press('?')
  const dialog = page.getByTestId('shortcuts-dialog')
  await expect(dialog).toBeVisible()
  await expect(dialog).toContainText('Week view')
  await expect(dialog.getByTestId('shortcuts-enabled')).toBeChecked()
  const saved = page.waitForRequest((sent) => sent.method() === 'PUT' && new URL(sent.url()).pathname === '/api/v1/account/ui-preferences')
  await dialog.getByTestId('shortcuts-enabled').click()
  expect(JSON.parse((await saved).postData() ?? '{}')).toMatchObject({ shortcuts: false })
  await page.keyboard.press('Escape')
  await expect(dialog).toBeHidden()

  // Off: the keys do nothing, after a reload too, from the account's copy
  // (this browser's own is cleared first).
  await page.keyboard.press('m')
  await expect.poll(view).toBe('week')
  await page.evaluate(() => localStorage.removeItem('kutup.shortcuts'))
  const read = page.waitForResponse((answer) => answer.request().method() === 'GET' && new URL(answer.url()).pathname === '/api/v1/account/ui-preferences')
  await page.reload()
  expect(((await (await read).json()) as { shortcuts: boolean | null }).shortcuts).toBe(false)
  await expect(page.getByTestId('calendar-list-item').first()).toBeVisible({ timeout: 120_000 })
  await page.keyboard.press('m')
  await page.keyboard.press('d')
  await expect.poll(view).toBe('week')
  await context.close()
})
