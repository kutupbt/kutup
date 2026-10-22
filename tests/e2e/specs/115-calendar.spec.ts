import { expect, test, type BrowserContext } from '@playwright/test'
import { appUrl, newAccount, registerAccount, signIn } from '../fixtures/apps'

const PASSWORD = 'Deneme123*CalendarPassword'
const WEEK = '/?view=week&date=2026-10-29'

/** Shows calendars in Istanbul's time, weeks from Monday, a 24-hour clock: what the times below are read in. */
async function istanbul(context: BrowserContext) {
  await context.addInitScript(() => {
    localStorage.setItem('kutup-calendar-prefs', JSON.stringify({ zone: 'Europe/Istanbul', weekStart: 1, hour12: false }))
  })
}

test('calendar: a first calendar, events in two time zones, week and month, edits, a second device, deletion', async ({ browser }) => {
  test.slow()
  const account = newAccount('calendar', PASSWORD)
  const context = await browser.newContext()
  await istanbul(context)
  await registerAccount(context, account)
  const page = await context.newPage()
  await page.goto(appUrl('calendar', WEEK))

  // The first open makes the account a calendar of its own.
  await expect(page.getByTestId('calendar-list-item').filter({ hasText: 'My calendar' })).toBeVisible({ timeout: 120_000 })
  await expect(page.getByTestId('calendar-title')).toHaveText('October 2026')

  // An event at nine on Thursday, moved to half past.
  await page.getByTestId('calendar-column-2026-10-29').locator('button').nth(9).click()
  const editor = page.getByRole('dialog', { name: 'New event' })
  await expect(editor.getByLabel('Start time')).toHaveValue('09:00')
  await editor.getByLabel('Title').fill('Republic Day lunch')
  await editor.getByLabel('Start time').fill('09:30')
  await editor.getByLabel('End time').fill('11:00')
  await editor.getByLabel('Location').fill('Moda, İstanbul')
  await editor.getByRole('button', { name: 'Save' }).click()
  await expect(page.getByText('Event created').last()).toBeVisible({ timeout: 30_000 })
  const thursday = page.getByTestId('calendar-column-2026-10-29')
  await expect(thursday.getByTestId('calendar-event').filter({ hasText: 'Republic Day lunch' })).toContainText('09:30')

  // One set in New York's time: 09:00 there (EDT, UTC−4) is 16:00 in Istanbul (UTC+3).
  await page.getByTestId('calendar-column-2026-10-30').locator('button').nth(9).click()
  const call = page.getByRole('dialog', { name: 'New event' })
  await call.getByLabel('Title').fill('Call with New York')
  await call.getByTestId('event-zone').click()
  await page.getByRole('option', { name: 'America/New York' }).click()
  await call.getByRole('button', { name: 'Save' }).click()
  await expect(call).toBeHidden({ timeout: 30_000 })
  await expect(page.getByTestId('calendar-column-2026-10-30').getByTestId('calendar-event').filter({ hasText: 'Call with New York' })).toContainText(
    '16:00',
  )

  // Edited: what was encrypted opens, and the change is saved.
  await thursday.getByTestId('calendar-event').filter({ hasText: 'Republic Day lunch' }).click()
  const edit = page.getByRole('dialog', { name: 'Event' })
  await expect(edit.getByLabel('Location')).toHaveValue('Moda, İstanbul')
  await edit.getByLabel('Title').fill('Republic Day dinner')
  await edit.getByRole('button', { name: 'Save' }).click()
  await expect(page.getByText('Event saved').last()).toBeVisible({ timeout: 30_000 })
  await expect(thursday.getByTestId('calendar-event').filter({ hasText: 'Republic Day dinner' })).toBeVisible()

  // The month, and an all-day event made from a day in it.
  await page.getByTestId('calendar-view-month').click()
  await expect(page.getByTestId('calendar-day-2026-10-29').getByTestId('calendar-event')).toContainText('Republic Day dinner')
  await page.getByTestId('calendar-day-2026-10-28').click()
  const allDay = page.getByRole('dialog', { name: 'New event' })
  await expect(allDay.getByLabel('All day')).toBeChecked()
  await allDay.getByLabel('Title').fill('Holiday eve')
  await allDay.getByRole('button', { name: 'Save' }).click()
  await expect(allDay).toBeHidden({ timeout: 30_000 })
  await expect(page.getByTestId('calendar-day-2026-10-28').getByTestId('calendar-event')).toContainText('Holiday eve')

  // After a reload, and on a second device signed in to the account.
  await page.reload()
  await expect(page.getByTestId('calendar-day-2026-10-29').getByTestId('calendar-event')).toContainText('Republic Day dinner', { timeout: 120_000 })
  const device = await browser.newContext()
  await istanbul(device)
  await signIn(device, account)
  const elsewhere = await device.newPage()
  await elsewhere.goto(appUrl('calendar', WEEK))
  await expect(elsewhere.getByTestId('calendar-column-2026-10-30').getByTestId('calendar-event').filter({ hasText: 'Call with New York' })).toContainText(
    '16:00',
    { timeout: 120_000 },
  )
  await device.close()

  // A second calendar, made and deleted.
  await page.getByTestId('calendar-new').click()
  const newCalendar = page.getByRole('dialog', { name: 'New calendar' })
  await newCalendar.getByLabel('Name').fill('Work')
  await newCalendar.getByRole('button', { name: 'Save' }).click()
  await expect(page.getByTestId('calendar-list-item').filter({ hasText: 'Work' })).toBeVisible({ timeout: 30_000 })
  await page.getByRole('button', { name: 'Edit Work' }).click()
  await page.getByRole('dialog', { name: 'Calendar' }).getByTestId('calendar-delete').click()
  await page.getByRole('button', { name: 'Delete calendar' }).last().click()
  await expect(page.getByTestId('calendar-list-item').filter({ hasText: 'Work' })).toHaveCount(0, { timeout: 30_000 })

  // An event deleted.
  await page.getByTestId('calendar-view-week').click()
  await thursday.getByTestId('calendar-event').filter({ hasText: 'Republic Day dinner' }).click()
  await page.getByRole('dialog', { name: 'Event' }).getByTestId('event-delete').click()
  await page.getByRole('button', { name: 'Delete event' }).last().click()
  await expect(thursday.getByTestId('calendar-event').filter({ hasText: 'Republic Day dinner' })).toHaveCount(0, { timeout: 30_000 })
  await context.close()
})
