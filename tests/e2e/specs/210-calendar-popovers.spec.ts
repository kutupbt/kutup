import { expect, test, type Locator, type Page } from '../fixtures/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Calendar's popovers and navigation, as Proton's (docs/plans/calendar.md,
// "Calendar UX parity"): a click or a drag on the grid opens the
// quick-create popover (a title, Save, "More options"); a click on an event
// its details (Edit, Duplicate, Delete), its links clickable and its
// description never read as HTML; Escape closes a popover and focus goes
// back; a day's header opens the day; "+N more" in the month lists the day;
// the mini calendar moves the view and opens a custom range. Istanbul's
// time, weeks from Monday, a 24-hour clock.

const PASSWORD = 'Deneme123*CalendarPopoverPassword'
const WEEK = '/?view=week&date=2026-10-29'

async function centre(locator: Locator): Promise<{ x: number; y: number }> {
  const box = (await locator.boundingBox())!
  return { x: box.x + box.width / 2, y: box.y + box.height / 2 }
}

async function drag(page: Page, from: { x: number; y: number }, to: { x: number; y: number }) {
  await page.mouse.move(from.x, from.y)
  await page.mouse.down()
  await page.mouse.move(to.x, to.y, { steps: 12 })
  await page.mouse.up()
}

const slot = (page: Page, day: string, index: number) => page.getByTestId(`calendar-slot-${day}-${index}`)

/** The grid with 08:00 at its top, so the slots used are on screen whenever the run is. */
async function fromEight(page: Page) {
  await page.getByTestId('calendar-scroller').evaluate((el) => {
    el.scrollTop = 8 * 48
  })
}

test('calendar popovers: quick create, details with links, duplicate, delete, day headers, "+N more", the mini calendar', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext({ viewport: { width: 1400, height: 1000 } })
  await context.addInitScript(() => {
    localStorage.setItem('kutup.calendar.prefs', JSON.stringify({ zone: 'Europe/Istanbul', weekStart: 1, hour12: false }))
    localStorage.setItem('kutup.calendar.notificationBannerDismissed', '1')
  })
  await registerAccount(context, newAccount('calpop', PASSWORD))
  const page = await context.newPage()
  await page.goto(appUrl('calendar', WEEK))
  await expect(page.getByTestId('calendar-list-item').filter({ hasText: 'My calendar' })).toBeVisible({ timeout: 120_000 })
  await fromEight(page)
  const thursday = page.getByTestId('calendar-column-2026-10-29')
  const quick = page.getByTestId('create-popover')

  // A click: the quick-create popover at 09:00, its draft drawn on the grid; a title and Enter save it.
  await slot(page, '2026-10-29', 18).click()
  await expect(quick).toBeVisible()
  await expect(page.getByTestId('create-popover-when')).toContainText('09:00 – 09:30')
  await expect(page.getByTestId('calendar-draft')).toBeVisible()
  await expect(page.getByTestId('create-popover-title')).toBeFocused()
  await page.getByTestId('create-popover-title').fill('Standup')
  await page.keyboard.press('Enter')
  await expect(page.getByText('Event created').last()).toBeVisible({ timeout: 30_000 })
  await expect(quick).toBeHidden()
  await expect(page.getByTestId('calendar-draft')).toHaveCount(0)
  await expect(thursday.getByTestId('calendar-event').filter({ hasText: 'Standup' })).toContainText('09:00 – 09:30')

  // Escape drops a new one; nothing is saved, focus goes back to the slot.
  await slot(page, '2026-10-29', 26).click()
  await expect(quick).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(quick).toBeHidden()
  await expect(slot(page, '2026-10-29', 26)).toBeFocused()

  // A drag: 14:00 to 16:00; "More options" opens the editor with the title typed.
  await drag(page, await centre(slot(page, '2026-10-28', 28)), await centre(slot(page, '2026-10-28', 31)))
  await expect(page.getByTestId('create-popover-when')).toContainText('14:00 – 16:00')
  await page.getByTestId('create-popover-title').fill('Review')
  await page.getByTestId('create-popover-more').click()
  const editor = page.getByRole('dialog', { name: 'New event' })
  await expect(editor.getByTestId('event-title')).toHaveValue('Review')
  await expect(editor.getByTestId('event-start-time')).toHaveValue('14:00')
  await expect(editor.getByTestId('event-end-time')).toHaveValue('16:00')
  // Links and markup in what anyone sharing a calendar could write.
  await editor.getByLabel('Location').fill('Room 4 https://maps.example/room4')
  await editor.getByLabel('Description').fill('Agenda: https://docs.example/agenda, mailto:team@example.com\n<img src=x onerror=alert(1)> <b>bold</b> javascript:alert(1)')
  await editor.getByTestId('event-save').click()
  await expect(editor).toBeHidden({ timeout: 30_000 })
  const wednesday = page.getByTestId('calendar-column-2026-10-28')
  const review = wednesday.getByTestId('calendar-event').filter({ hasText: 'Review' })
  await expect(review).toContainText('14:00 – 16:00')

  // Its details: when, the zone, where, the calendar, its links (http, https and mailto only), its notifications.
  await review.click()
  const peek = page.getByTestId('event-popover')
  await expect(peek).toBeVisible()
  await expect(page.getByTestId('event-popover-title')).toHaveText('Review')
  await expect(page.getByTestId('event-popover-when')).toHaveText(/^Wednesday, (28 October|October 28), 2026, 14:00 – 16:00$/)
  await expect(page.getByTestId('event-popover-zone')).toHaveText('Europe/Istanbul')
  await expect(page.getByTestId('event-popover-calendar')).toHaveText('My calendar')
  await expect(page.getByTestId('event-popover-reminders')).toBeVisible()
  const place = page.getByTestId('event-popover-location').getByRole('link', { name: 'https://maps.example/room4' })
  await expect(place).toHaveAttribute('href', 'https://maps.example/room4')
  await expect(place).toHaveAttribute('rel', 'noopener noreferrer')
  await expect(place).toHaveAttribute('target', '_blank')
  const description = page.getByTestId('event-popover-description')
  await expect(description.getByRole('link')).toHaveCount(2)
  await expect(description.getByRole('link', { name: 'https://docs.example/agenda' })).toHaveAttribute('href', 'https://docs.example/agenda')
  await expect(description.getByRole('link', { name: 'mailto:team@example.com' })).toHaveAttribute('href', 'mailto:team@example.com')
  await expect(description).toContainText('<img src=x onerror=alert(1)> <b>bold</b> javascript:alert(1)')
  await expect(description.locator('img, b')).toHaveCount(0)
  // Escape closes it; focus goes back to the event.
  await page.keyboard.press('Escape')
  await expect(peek).toBeHidden()
  await expect(review).toBeFocused()

  // Duplicate: the editor, a new event with everything copied.
  await review.click()
  await page.getByTestId('event-popover-duplicate').click()
  await expect(editor.getByTestId('event-title')).toHaveValue('Review')
  await expect(editor.getByLabel('Location')).toHaveValue('Room 4 https://maps.example/room4')
  await expect(editor.getByTestId('event-start-date')).toHaveValue('2026-10-28')
  await editor.getByTestId('event-start-date').fill('2026-10-30')
  await editor.getByTestId('event-end-date').fill('2026-10-30')
  await editor.getByTestId('event-save').click()
  await expect(editor).toBeHidden({ timeout: 30_000 })
  await expect(page.getByTestId('calendar-column-2026-10-30').getByTestId('calendar-event').filter({ hasText: 'Review' })).toContainText('14:00 – 16:00')
  await expect(review).toHaveCount(1)

  // A repeating event's duplicate repeats as it does (Proton's).
  await slot(page, '2026-10-26', 20).click()
  await page.getByTestId('create-popover-title').fill('Weekly')
  await page.getByTestId('create-popover-more').click()
  await editor.getByTestId('event-repeat').click()
  await page.getByRole('option', { name: 'Every week on Monday' }).click()
  await editor.getByTestId('event-save').click()
  await expect(page.getByText('Events created').last()).toBeVisible({ timeout: 30_000 })
  const weekly = page.getByTestId('calendar-column-2026-10-26').getByTestId('calendar-event').filter({ hasText: 'Weekly' })
  await weekly.click()
  await expect(page.getByTestId('event-popover-repeat')).toHaveText('Weekly on Monday')
  await page.getByTestId('event-popover-duplicate').click()
  await expect(editor.getByTestId('event-repeat')).toContainText('Every week on Monday')
  await editor.getByRole('button', { name: 'Cancel' }).click()
  await expect(editor).toBeHidden()

  // Delete from the popover: confirmed, then gone.
  await page.getByTestId('calendar-column-2026-10-30').getByTestId('calendar-event').filter({ hasText: 'Review' }).click()
  await page.getByTestId('event-popover-delete').click()
  await page.getByRole('button', { name: 'Delete event' }).last().click()
  await expect(page.getByText('Event deleted').last()).toBeVisible({ timeout: 30_000 })
  await expect(page.getByTestId('calendar-column-2026-10-30').getByTestId('calendar-event')).toHaveCount(0)

  // A day's header opens that day.
  await page.getByTestId('calendar-day-link-2026-10-28').click()
  await expect(page).toHaveURL(/view=day/)
  await expect(page).toHaveURL(/date=2026-10-28/)
  await expect(page.getByTestId('calendar-title')).toHaveText(/^Wednesday, (28 October|October 28),? 2026$/)
  await expect(page.getByTestId('calendar-column-2026-10-28').getByTestId('calendar-event')).toContainText('Review')

  // The month: four on one day show three and "+1 more", which lists them all.
  await page.getByTestId('calendar-view-week').click()
  await fromEight(page)
  for (const [index, title] of [
    [22, 'Lunch'],
    [30, 'Call'],
  ] as const) {
    await slot(page, '2026-10-29', index).click()
    await page.getByTestId('create-popover-title').fill(title)
    await page.getByTestId('create-popover-save').click()
    await expect(quick).toBeHidden({ timeout: 30_000 })
    await expect(thursday.getByTestId('calendar-event').filter({ hasText: title })).toBeVisible()
  }
  // An all-day one too, from the all-day row.
  const row = (await page.getByTestId('calendar-allday-2026-10-29').boundingBox())!
  await page.mouse.click(row.x + 10, row.y + row.height - 3)
  await page.getByTestId('create-popover-title').fill('Holiday')
  await page.getByTestId('create-popover-save').click()
  await expect(quick).toBeHidden({ timeout: 30_000 })
  await page.getByTestId('calendar-view-month').click()
  const day = page.getByTestId('calendar-day-2026-10-29')
  await expect(day.getByTestId('calendar-event')).toHaveCount(3)
  const more = day.getByTestId('calendar-more')
  await expect(more).toHaveText('1 more')
  await more.click()
  const list = page.getByTestId('more-popover')
  await expect(list).toContainText(/Thursday, (29 October|October 29),? 2026/)
  await expect(list.getByTestId('calendar-event')).toHaveCount(4)
  await expect(list.getByTestId('calendar-event').first()).toContainText('Holiday')
  // One of them opens its details; Escape gives focus back to "+1 more".
  await list.getByTestId('calendar-event').filter({ hasText: 'Call' }).click()
  await expect(page.getByTestId('event-popover-title')).toHaveText('Call')
  await page.keyboard.press('Escape')
  await expect(page.getByTestId('event-popover')).toBeHidden()
  await expect(more).toBeFocused()
  // A month's day number opens the day too.
  await page.getByTestId('calendar-day-link-2026-10-29').click()
  await expect(page.getByTestId('calendar-title')).toHaveText(/^Thursday, (29 October|October 29),? 2026$/)

  // The mini calendar: a day goes there in the view shown; its arrows step months without moving the view.
  const mini = page.getByTestId('mini-calendar')
  await expect(page.getByTestId('mini-calendar-month')).toHaveText('October 2026')
  await expect(page.getByTestId('mini-day-2026-10-29')).toHaveAttribute('aria-pressed', 'true')
  await page.getByTestId('mini-day-2026-10-27').click()
  await expect(page.getByTestId('calendar-title')).toHaveText(/^Tuesday, (27 October|October 27),? 2026$/)
  await page.getByTestId('mini-calendar-next').click()
  await expect(page.getByTestId('mini-calendar-month')).toHaveText('November 2026')
  await expect(page.getByTestId('calendar-title')).toHaveText(/^Tuesday, (27 October|October 27),? 2026$/)
  // The keyboard: arrows move between days, Enter goes there.
  await page.getByTestId('mini-day-2026-11-04').focus()
  await page.keyboard.press('ArrowRight')
  await expect(page.getByTestId('mini-day-2026-11-05')).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(page.getByTestId('calendar-title')).toHaveText(/^Thursday, (5 November|November 5),? 2026$/)
  // A drag across three days shows those three (Proton's custom range), the days marked.
  await drag(page, await centre(page.getByTestId('mini-day-2026-11-10')), await centre(page.getByTestId('mini-day-2026-11-12')))
  await expect(page).toHaveURL(/view=week/)
  await expect(page).toHaveURL(/range=2/)
  await expect(page.locator('[data-testid^="calendar-column-"]')).toHaveCount(3)
  await expect(page.getByTestId('calendar-column-2026-11-10')).toBeVisible()
  await expect(page.getByTestId('calendar-column-2026-11-12')).toBeVisible()
  await expect(mini.getByTestId('mini-day-2026-11-11')).toHaveAttribute('aria-pressed', 'true')
  // Next steps by the range's length; the week tab gives the whole week back.
  await page.getByTestId('calendar-next').click()
  await expect(page.getByTestId('calendar-column-2026-11-13')).toBeVisible()
  await expect(page.locator('[data-testid^="calendar-column-"]')).toHaveCount(3)
  await page.getByTestId('calendar-view-week').click()
  await expect(page.locator('[data-testid^="calendar-column-"]')).toHaveCount(7)
  // Across two weeks: a month view of those weeks.
  await drag(page, await centre(page.getByTestId('mini-day-2026-11-02')), await centre(page.getByTestId('mini-day-2026-11-15')))
  await expect(page).toHaveURL(/view=month/)
  await expect(page.locator('[data-testid^="calendar-day-2026-"]')).toHaveCount(14)
  await context.close()
})
