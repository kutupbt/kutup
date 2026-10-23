import { expect, test, type Locator, type Page } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'

// The time grid by pointer and keyboard (docs/plans/calendar.md, "Calendar
// UX parity"), as Proton's: press and drag to make an event, snapped to 30
// minutes, down or up; a click makes one of the default 30 minutes; Escape
// cancels a drag; an event dragged moves (across days too), its bottom edge
// resizes it, each opening the editor with the new times, saved by Save;
// the all-day row takes a drag across days; the keyboard makes a span with
// Shift and the arrows. Istanbul's time, weeks from Monday, a 24-hour clock.

const PASSWORD = 'Deneme123*CalendarDragPassword'
const WEEK = '/?view=week&date=2026-10-29'

async function centre(locator: Locator): Promise<{ x: number; y: number }> {
  const box = (await locator.boundingBox())!
  return { x: box.x + box.width / 2, y: box.y + box.height / 2 }
}

/** Presses at `from`, drags in steps to `to`, and lets go (unless `release` is false). */
async function drag(page: Page, from: { x: number; y: number }, to: { x: number; y: number }, release = true) {
  await page.mouse.move(from.x, from.y)
  await page.mouse.down()
  await page.mouse.move(to.x, to.y, { steps: 12 })
  if (release) await page.mouse.up()
}

const slot = (page: Page, day: string, index: number) => page.getByTestId(`calendar-slot-${day}-${index}`)

/**
 * The grid scrolled to 08:00 at its top (it opens at the time of day now,
 * which a run can't choose): the slots the test drags between are on
 * screen whenever it runs.
 */
async function fromEight(page: Page) {
  await page.getByTestId('calendar-scroller').evaluate((el) => {
    el.scrollTop = 8 * 48
  })
}

test('calendar grid: drag to make, move and resize events; the all-day row; the keyboard', async ({ browser }) => {
  test.slow()
  const account = newAccount('caldrag', PASSWORD)
  const context = await browser.newContext({ viewport: { width: 1400, height: 1000 } })
  await context.addInitScript(() => {
    localStorage.setItem('kutup-calendar-prefs', JSON.stringify({ zone: 'Europe/Istanbul', weekStart: 1, hour12: false }))
  })
  await registerAccount(context, account)
  const page = await context.newPage()
  await page.goto(appUrl('calendar', WEEK))
  await expect(page.getByTestId('calendar-list-item').filter({ hasText: 'My calendar' })).toBeVisible({ timeout: 120_000 })
  const editor = page.getByRole('dialog', { name: 'New event' })
  const times = async (dialog: Locator, start: string, end: string) => {
    await expect(dialog.getByTestId('event-start-time')).toHaveValue(start)
    await expect(dialog.getByTestId('event-end-time')).toHaveValue(end)
  }
  await fromEight(page)

  // Down: from 10:00 to the 11:30 slot is 10:00–12:00, the editor filled in.
  await drag(page, await centre(slot(page, '2026-10-29', 20)), await centre(slot(page, '2026-10-29', 23)))
  await times(editor, '10:00', '12:00')
  await expect(editor.getByTestId('event-start-date')).toHaveValue('2026-10-29')
  await editor.getByTestId('event-title').fill('Planning')
  await editor.getByTestId('event-save').click()
  await expect(editor).toBeHidden({ timeout: 30_000 })
  const thursday = page.getByTestId('calendar-column-2026-10-29')
  const planning = thursday.getByTestId('calendar-event').filter({ hasText: 'Planning' })
  await expect(planning).toContainText('10:00 – 12:00')

  // Up: from the 15:00 slot to the 14:00 one is 14:00–15:00.
  await drag(page, await centre(slot(page, '2026-10-28', 30)), await centre(slot(page, '2026-10-28', 28)))
  await times(editor, '14:00', '15:00')
  await editor.getByRole('button', { name: 'Cancel' }).click()
  await expect(editor).toBeHidden()

  // Escape mid-drag: nothing opens, nothing is left drawn.
  await drag(page, await centre(slot(page, '2026-10-27', 20)), await centre(slot(page, '2026-10-27', 24)), false)
  await expect(page.getByTestId('calendar-ghost')).toBeVisible()
  await page.keyboard.press('Escape')
  await page.mouse.up()
  await expect(page.getByTestId('calendar-ghost')).toHaveCount(0)
  await expect(editor).toBeHidden()

  // A click: 17:00, the default 30 minutes.
  await slot(page, '2026-10-30', 34).click()
  await times(editor, '17:00', '17:30')
  await editor.getByRole('button', { name: 'Cancel' }).click()

  // Moved: an hour later and a day on (the editor shows it; Save keeps it).
  await fromEight(page)
  const from = await centre(planning)
  const hourBelow = (await centre(slot(page, '2026-10-30', 24))).y - (await centre(slot(page, '2026-10-30', 22))).y
  const friday = await centre(page.getByTestId('calendar-column-2026-10-30'))
  await drag(page, from, { x: friday.x, y: from.y + hourBelow })
  const moved = page.getByRole('dialog', { name: 'Event' })
  await expect(moved.getByTestId('event-start-date')).toHaveValue('2026-10-30')
  await times(moved, '11:00', '13:00')
  await moved.getByTestId('event-save').click()
  await expect(moved).toBeHidden({ timeout: 30_000 })
  const onFriday = page.getByTestId('calendar-column-2026-10-30').getByTestId('calendar-event').filter({ hasText: 'Planning' })
  await expect(onFriday).toContainText('11:00 – 13:00')
  await expect(planning).toHaveCount(0)

  // Resized by its bottom edge to the 14:00 slot: it ends at 14:30.
  const box = (await onFriday.boundingBox())!
  await drag(page, { x: box.x + box.width / 2, y: box.y + box.height - 2 }, await centre(slot(page, '2026-10-30', 28)))
  await times(moved, '11:00', '14:30')
  await moved.getByTestId('event-save').click()
  await expect(onFriday).toContainText('11:00 – 14:30', { timeout: 30_000 })

  // The all-day row: Tuesday to Thursday, one event.
  await drag(page, await centre(page.getByTestId('calendar-allday-2026-10-27')), await centre(page.getByTestId('calendar-allday-2026-10-29')))
  await expect(editor.getByTestId('event-all-day')).toBeChecked()
  await expect(editor.getByTestId('event-start-date')).toHaveValue('2026-10-27')
  await expect(editor.getByTestId('event-end-date')).toHaveValue('2026-10-29')
  await editor.getByRole('button', { name: 'Cancel' }).click()

  // The keyboard: 09:00 on Monday, Shift+↓ three times, Enter: 09:00–11:00.
  await slot(page, '2026-10-26', 18).focus()
  for (let i = 0; i < 3; i++) await page.keyboard.press('Shift+ArrowDown')
  await expect(page.getByTestId('calendar-announce')).toContainText('09:00 to 11:00')
  await page.keyboard.press('Enter')
  await times(editor, '09:00', '11:00')
  await expect(editor.getByTestId('event-start-date')).toHaveValue('2026-10-26')
  await editor.getByRole('button', { name: 'Cancel' }).click()

  // An event moved by keyboard: Alt+↓ twice is an hour later.
  await onFriday.focus()
  await page.keyboard.press('Alt+ArrowDown')
  await page.keyboard.press('Alt+ArrowDown')
  await page.keyboard.press('Enter')
  await times(moved, '12:00', '15:30')
  await moved.getByRole('button', { name: 'Cancel' }).click()

  // Today: the current time's line.
  await page.keyboard.press('t')
  await expect(page.getByTestId('calendar-now')).toBeVisible()

  await context.close()
})
