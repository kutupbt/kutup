import { expect, test, type BrowserContext, type Page } from '../fixtures/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'

const PASSWORD = 'Deneme123*CalendarRecurrence'

/** Calendars in Berlin's time (summer time ends 25 October 2026), weeks from Monday, a 24-hour clock. */
async function berlin(context: BrowserContext) {
  await context.addInitScript(() => {
    localStorage.setItem('kutup.calendar.prefs', JSON.stringify({ zone: 'Europe/Berlin', weekStart: 1, hour12: false }))
  })
}

function eventsOn(page: Page, day: string, title?: string) {
  const all = page.getByTestId(`calendar-column-${day}`).getByTestId('calendar-event')
  return title ? all.filter({ hasText: title }) : all
}

async function week(page: Page, date: string) {
  await page.goto(appUrl('calendar', `/?view=week&date=${date}`))
}

test('calendar: a weekly series across summer time, one occurrence changed, one deleted, this and future, all deleted', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await berlin(context)
  await registerAccount(context, newAccount('calrecur', PASSWORD))
  const page = await context.newPage()
  await week(page, '2026-10-19')
  await expect(page.getByTestId('calendar-list-item').filter({ hasText: 'My calendar' })).toBeVisible({ timeout: 120_000 })

  // Mondays at nine, from 19 October: Proton's "Every week on Monday".
  await page.getByTestId('calendar-slot-2026-10-19-18').click()
  await page.getByTestId('create-popover-more').click()
  const editor = page.getByRole('dialog', { name: 'New event' })
  await editor.getByLabel('Title').fill('Weekly sync')
  await editor.getByTestId('event-repeat').click()
  await page.getByRole('option', { name: 'Every week on Monday' }).click()
  await editor.getByRole('button', { name: 'Save' }).click()
  await expect(page.getByText('Events created').last()).toBeVisible({ timeout: 30_000 })
  await expect(eventsOn(page, '2026-10-19', 'Weekly sync')).toContainText('09:00')

  // Every week, still at nine after summer time ends (25 October).
  await page.getByTestId('calendar-next').click()
  await expect(eventsOn(page, '2026-10-26', 'Weekly sync')).toContainText('09:00', { timeout: 30_000 })
  await page.getByTestId('calendar-next').click()
  await expect(eventsOn(page, '2026-11-02', 'Weekly sync')).toContainText('09:00', { timeout: 30_000 })
  await page.getByTestId('calendar-view-month').click()
  for (const day of ['2026-11-09', '2026-11-16', '2026-11-23', '2026-11-30']) {
    await expect(page.getByTestId(`calendar-day-${day}`).getByTestId('calendar-event')).toContainText('Weekly sync')
  }

  // One occurrence moved and renamed: "This event".
  await week(page, '2026-10-26')
  await eventsOn(page, '2026-10-26', 'Weekly sync').click()
  await expect(page.getByTestId('event-popover-repeat')).toHaveText('Weekly on Monday')
  await page.getByTestId('event-popover-edit').click()
  const edit = page.getByRole('dialog', { name: 'Event', exact: true })
  await expect(edit.getByLabel('Starts')).toHaveValue('2026-10-26')
  await expect(edit.getByTestId('event-repeat')).toContainText('Every week on Monday')
  await edit.getByLabel('Title').fill('Moved sync')
  await edit.getByLabel('Start time').fill('11:00')
  await edit.getByLabel('End time').fill('12:00')
  await edit.getByRole('button', { name: 'Save' }).click()
  const update = page.getByRole('dialog', { name: 'Update recurring event' })
  await expect(update.getByTestId('recurring-option-single')).toBeChecked()
  await update.getByRole('button', { name: 'Update' }).click()
  await expect(page.getByText('Event saved').last()).toBeVisible({ timeout: 30_000 })
  await expect(eventsOn(page, '2026-10-26', 'Moved sync')).toContainText('11:00')
  await expect(eventsOn(page, '2026-10-26', 'Weekly sync')).toHaveCount(0)

  // One occurrence deleted: "This event" (an EXDATE on the series).
  await week(page, '2026-11-02')
  // From its popover (Proton's Delete there asks the same).
  await eventsOn(page, '2026-11-02', 'Weekly sync').click()
  await page.getByTestId('event-popover-delete').click()
  const remove = page.getByRole('dialog', { name: 'Delete recurring event' })
  await expect(remove.getByTestId('recurring-option-future')).toBeVisible()
  await remove.getByTestId('recurring-option-single').check()
  await remove.getByRole('button', { name: 'Delete' }).click()
  await expect(page.getByText('Event deleted').last()).toBeVisible({ timeout: 30_000 })
  await expect(eventsOn(page, '2026-11-02')).toHaveCount(0)

  // From 9 November on, renamed: "This and future events" splits the series.
  await week(page, '2026-11-09')
  await eventsOn(page, '2026-11-09', 'Weekly sync').click()
  await page.getByTestId('event-popover-edit').click()
  const future = page.getByRole('dialog', { name: 'Event', exact: true })
  await future.getByLabel('Title').fill('Later sync')
  await future.getByRole('button', { name: 'Save' }).click()
  const which = page.getByRole('dialog', { name: 'Update recurring event' })
  await which.getByTestId('recurring-option-future').check()
  await which.getByRole('button', { name: 'Update' }).click()
  await expect(page.getByText('Future events updated').last()).toBeVisible({ timeout: 30_000 })
  await expect(eventsOn(page, '2026-11-09', 'Later sync')).toContainText('09:00')
  await page.getByTestId('calendar-next').click()
  await expect(eventsOn(page, '2026-11-16', 'Later sync')).toBeVisible({ timeout: 30_000 })
  // Before it, the series as it was (and its changed occurrence).
  await week(page, '2026-10-19')
  await expect(eventsOn(page, '2026-10-19', 'Weekly sync')).toBeVisible({ timeout: 30_000 })
  await page.getByTestId('calendar-next').click()
  await expect(eventsOn(page, '2026-10-26', 'Moved sync')).toBeVisible({ timeout: 30_000 })

  // The first series deleted whole: "All events", its changed occurrence with it.
  await page.getByTestId('calendar-previous').click()
  await eventsOn(page, '2026-10-19', 'Weekly sync').click()
  await page.getByTestId('event-popover-edit').click()
  await page.getByRole('dialog', { name: 'Event', exact: true }).getByTestId('event-delete').click()
  const all = page.getByRole('dialog', { name: 'Delete recurring event' })
  // The first occurrence: no "this and future".
  await expect(all.getByTestId('recurring-option-future')).toHaveCount(0)
  await all.getByTestId('recurring-option-all').check()
  await all.getByRole('button', { name: 'Delete' }).click()
  await expect(page.getByText('All events deleted').last()).toBeVisible({ timeout: 30_000 })
  await expect(eventsOn(page, '2026-10-19')).toHaveCount(0)
  await page.getByTestId('calendar-next').click()
  await expect(eventsOn(page, '2026-10-26')).toHaveCount(0, { timeout: 30_000 })

  // The later series stays, after a reload too; then it goes as well.
  await week(page, '2026-11-16')
  await expect(eventsOn(page, '2026-11-16', 'Later sync')).toBeVisible({ timeout: 120_000 })
  await eventsOn(page, '2026-11-16', 'Later sync').click()
  await page.getByTestId('event-popover-delete').click()
  const rest = page.getByRole('dialog', { name: 'Delete recurring event' })
  await rest.getByTestId('recurring-option-all').check()
  await rest.getByRole('button', { name: 'Delete' }).click()
  await expect(page.getByText('All events deleted').last()).toBeVisible({ timeout: 30_000 })
  await expect(eventsOn(page, '2026-11-16')).toHaveCount(0)
  await page.getByTestId('calendar-previous').click()
  await expect(eventsOn(page, '2026-11-09')).toHaveCount(0, { timeout: 30_000 })
  await context.close()
})
