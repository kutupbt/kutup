import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Reminders in the app (docs/plans/calendar.md, E2b-3), as Proton's: an
// event's notifications in the editor (the calendar's defaults until edited,
// saved as its own); a calendar's default notifications; and, while Calendar
// is open, its reminder firing as a desktop notification named by the
// event's title ("… starts now"). Istanbul's time, a 24-hour clock.

const PASSWORD = 'Deneme123*CalendarRemindersPassword'
const ZONE = 'Europe/Istanbul'

type Shown = { title: string; body: string }

/** The browser's notifications (a page's and a service worker's), recorded instead of shown; permission granted. */
async function recordNotifications(context: BrowserContext) {
  await context.addInitScript(() => {
    const shown: Shown[] = []
    class Recorded {
      static get permission() {
        return 'granted'
      }
      static requestPermission() {
        return Promise.resolve('granted')
      }
      onclick: (() => void) | null = null
      constructor(title: string, options?: NotificationOptions) {
        shown.push({ title, body: options?.body ?? '' })
      }
      close() {}
    }
    Object.defineProperty(window, 'Notification', { value: Recorded, configurable: true })
    if (typeof ServiceWorkerRegistration !== 'undefined') {
      ServiceWorkerRegistration.prototype.showNotification = function (title: string, options?: NotificationOptions) {
        shown.push({ title, body: options?.body ?? '' })
        return Promise.resolve()
      }
    }
    Object.defineProperty(window, '__shown', { value: shown })
  })
}

const shown = (page: Page) => page.evaluate(() => (window as unknown as { __shown: Shown[] }).__shown)

/** `yyyy-MM-dd` and `HH:mm` in Istanbul, `minutes` from now on a whole minute. */
function istanbul(minutes: number): { date: string; time: string } {
  const at = new Date(Math.ceil(Date.now() / 60_000) * 60_000 + minutes * 60_000)
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat('en-GB', { timeZone: ZONE, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })
      .formatToParts(at)
      .map((p) => [p.type, p.value]),
  )
  return { date: `${parts.year}-${parts.month}-${parts.day}`, time: `${parts.hour}:${parts.minute}` }
}

test('calendar reminders: the editor, a calendar’s defaults, and one firing while Calendar is open', async ({ browser }) => {
  test.slow()
  const account = newAccount('calremind', PASSWORD)
  const context = await browser.newContext({ viewport: { width: 1400, height: 1000 } })
  await context.addInitScript((zone) => {
    localStorage.setItem('kutup-calendar-prefs', JSON.stringify({ zone, weekStart: 1, hour12: false }))
  }, ZONE)
  await recordNotifications(context)
  await registerAccount(context, account)
  const page = await context.newPage()
  await page.goto(appUrl('calendar'))
  await expect(page.getByTestId('calendar-list-item').filter({ hasText: 'My calendar' })).toBeVisible({ timeout: 120_000 })

  // A calendar's defaults (Proton's): 30 minutes before, for timed events.
  await page.getByRole('button', { name: 'Edit My calendar' }).click()
  const settings = page.getByRole('dialog', { name: 'Calendar' })
  const timed = settings.getByTestId('calendar-timed-reminders')
  await expect(timed.getByTestId('reminder-row')).toHaveCount(2)
  await timed.getByRole('spinbutton', { name: 'How many' }).first().fill('30')
  await settings.getByRole('button', { name: 'Save' }).click()
  await expect(settings).toBeHidden({ timeout: 30_000 })

  // A new event starts with them; this one's own: at the time of the event.
  const start = istanbul(2)
  const end = istanbul(32)
  await page.keyboard.press('n')
  const editor = page.getByRole('dialog', { name: 'New event' })
  const reminders = editor.getByTestId('event-reminders')
  await expect(reminders.getByRole('spinbutton', { name: 'How many' }).first()).toHaveValue('30')
  await editor.getByLabel('Title').fill('Toplantı')
  await editor.getByTestId('event-start-date').fill(start.date)
  await editor.getByLabel('Start time').fill(start.time)
  await editor.getByTestId('event-end-date').fill(end.date)
  await editor.getByLabel('End time').fill(end.time)
  // One reminder, at the time of the event.
  await reminders.getByRole('button', { name: 'Remove this notification' }).last().click()
  await reminders.getByRole('combobox', { name: 'When' }).click()
  await page.getByRole('option', { name: 'at time of event' }).click()
  await editor.getByRole('button', { name: 'Save' }).click()
  await expect(page.getByText('Event created').last()).toBeVisible({ timeout: 30_000 })

  // It fires here, named by its title, within a minute of its start.
  await expect
    .poll(async () => (await shown(page)).find((n) => n.title === 'Calendar reminder')?.body ?? '', { timeout: 4 * 60_000, intervals: [5_000] })
    .toMatch(/^Toplantı (starts now|starts at|started at)/)

  // Opened again, the event shows its own reminder.
  await page.goto(appUrl('calendar', `/?view=day&date=${start.date}`))
  await page.getByTestId('calendar-event').filter({ hasText: 'Toplantı' }).first().click()
  const opened = page.getByRole('dialog', { name: 'Event' })
  await expect(opened.getByTestId('reminder-row')).toHaveCount(1)
  await expect(opened.getByRole('combobox', { name: 'When' })).toContainText('at time of event')
  await context.close()
})
