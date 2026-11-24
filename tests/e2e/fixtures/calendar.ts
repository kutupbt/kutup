import { expect, type Browser, type BrowserContext, type Page } from './test'
import { appUrl, newAccount, registerAccount, type Account } from './apps'

// Calendar sharing's specs (201-206, docs/plans/calendar-e3.md): accounts
// in Istanbul's time with a 24-hour clock, weeks from Monday, and the week
// of today, where the events they make fall.

export const ZONE = 'Europe/Istanbul'

/** Today in Istanbul, `yyyy-MM-dd`. */
export function today(): string {
  return new Intl.DateTimeFormat('en-CA', { timeZone: ZONE, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date())
}

/** A context in Istanbul's time, its calendar preferences set. */
export async function istanbulContext(browser: Browser): Promise<BrowserContext> {
  const context = await browser.newContext({ timezoneId: ZONE, viewport: { width: 1400, height: 1000 } })
  await context.addInitScript((zone) => {
    localStorage.setItem('kutup.calendar.prefs', JSON.stringify({ zone, weekStart: 1, hour12: false }))
  }, ZONE)
  return context
}

/** A new account with Calendar open on this week, its first calendar made and named `name`. */
export async function calendarAccount(browser: Browser, prefix: string, password: string, name?: string): Promise<{ account: Account; context: BrowserContext; page: Page }> {
  const account = newAccount(prefix, password)
  const context = await istanbulContext(browser)
  await registerAccount(context, account)
  const page = await context.newPage()
  await openWeek(page)
  if (name) await renameCalendar(page, 'My calendar', name)
  return { account, context, page }
}

/** Calendar on this week, the account's own calendar listed. */
export async function openWeek(page: Page): Promise<void> {
  await page.goto(appUrl('calendar', `/?view=week&date=${today()}`))
  await expect(page.getByTestId('calendar-list-item').first()).toBeVisible({ timeout: 120_000 })
}

export async function renameCalendar(page: Page, from: string, to: string): Promise<void> {
  await expect(page.getByTestId('calendar-list-item').filter({ hasText: from })).toBeVisible({ timeout: 120_000 })
  await page.getByRole('button', { name: `Edit ${from}` }).click()
  const dialog = page.getByRole('dialog', { name: 'Calendar' })
  await dialog.getByTestId('calendar-name').fill(to)
  await dialog.getByTestId('calendar-save').click()
  await expect(dialog).toBeHidden({ timeout: 30_000 })
  await expect(page.getByTestId('calendar-list-item').filter({ hasText: to })).toBeVisible({ timeout: 30_000 })
}

/**
 * An event today from `hour` for an hour, titled `title`, in the calendar
 * `calendar` when given (else the editor's first writable one).
 */
export async function addEvent(page: Page, hour: number, title: string, calendar?: string): Promise<void> {
  await page.getByTestId(`calendar-slot-${today()}-${hour * 2}`).click()
  // The quick-create popover first; "More options" opens the editor.
  await page.getByTestId('create-popover-more').click()
  const editor = page.getByRole('dialog', { name: 'New event' })
  await editor.getByLabel('Title').fill(title)
  if (calendar) {
    await editor.getByLabel('Calendar', { exact: true }).click()
    await page.getByRole('option', { name: calendar, exact: true }).click()
  }
  await editor.getByRole('button', { name: 'Save' }).click()
  await expect(editor).toBeHidden({ timeout: 30_000 })
  await expect(eventsToday(page).filter({ hasText: title })).toBeVisible({ timeout: 30_000 })
}

export function eventsToday(page: Page) {
  return page.getByTestId(`calendar-column-${today()}`).getByTestId('calendar-event')
}

/** The share dialog of the owner's calendar `name`. */
export async function openSharing(page: Page, name: string) {
  await page.getByTestId('calendar-list-item').filter({ hasText: name }).hover()
  await page.getByRole('button', { name: `Share ${name}` }).click()
  const dialog = page.getByTestId('calendar-share')
  await expect(dialog).toBeVisible()
  return dialog
}

/** Invites `address` from the open share dialog with the preset named `preset`. */
export async function invite(page: Page, dialog: ReturnType<Page['getByTestId']>, address: string, preset: 'Edit event details' | 'See all event details') {
  await dialog.getByTestId('share-address').fill(address)
  await dialog.getByRole('combobox', { name: 'What they can do' }).click()
  await page.getByRole('option', { name: preset, exact: true }).click()
  await dialog.getByTestId('share-invite').click()
  await expect(page.getByText(`Invitation sent to ${address}`).last()).toBeVisible({ timeout: 60_000 })
  await expect(dialog.getByTestId('share-members')).toContainText(address, { timeout: 30_000 })
}

/** The invitation from `owner`, opened and joined. */
export async function joinFrom(page: Page, owner: Account, calendar: string): Promise<void> {
  const row = page.getByTestId('calendar-invitation').filter({ hasText: owner.address })
  await expect(row).toBeVisible({ timeout: 60_000 })
  await row.click()
  const dialog = page.getByTestId('invitation-dialog')
  await expect(dialog.getByRole('heading', { name: `Join ${calendar}` })).toBeVisible({ timeout: 60_000 })
  await dialog.getByTestId('invitation-join').click()
  await expect(dialog).toBeHidden({ timeout: 60_000 })
  await expect(page.getByTestId('calendar-list-item').filter({ hasText: calendar })).toBeVisible({ timeout: 60_000 })
}
