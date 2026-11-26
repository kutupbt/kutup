import { expect, test } from '../fixtures/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Kutup meetings in events (docs/plans/calendar.md, E5c): "Add Kutup
// meeting" in the event editor makes a Chat meeting titled and timed as the
// event, its link kept in the event's encrypted part only (the server never
// sees it, nor the title); the event's details offer Join; the meeting is in
// Chat's list; and Chat's "Add to Kutup Calendar" opens the editor filled
// in. Needs the call server (docker compose --profile sfu), as spec 41.

const PASSWORD = 'Deneme123*CalendarMeetingPassword'

test('a Kutup meeting is added to an event, joined from it, and added back from Chat', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext({ viewport: { width: 1400, height: 1000 } })
  await context.addInitScript(() => {
    localStorage.setItem('kutup.calendar.prefs', JSON.stringify({ zone: 'UTC', weekStart: 1, hour12: false }))
    localStorage.setItem('kutup.calendar.notificationBannerDismissed', '1')
  })
  await registerAccount(context, newAccount('calmeet', PASSWORD))
  const page = await context.newPage()
  await page.goto(appUrl('calendar', '/?view=week&date=2031-05-06'))
  await expect(page.getByTestId('calendar-list-item').filter({ hasText: 'My calendar' })).toBeVisible({ timeout: 120_000 })
  const settings = (await (await page.request.get(apiUrl('/auth/settings'))).json()) as { chat: { callLinks?: boolean } }
  test.skip(settings.chat.callLinks !== true, 'this stack has no SFU (docker compose --profile sfu)')

  // The editor: a title, a time, then the meeting. What reaches the server
  // for the meeting is sealed: never the title, and never the link.
  // Tuesday 14:00 (slot 28), "More options" for the whole editor.
  await page.getByTestId('calendar-scroller').evaluate((el) => {
    el.scrollTop = 12 * 48
  })
  await page.getByTestId('calendar-slot-2031-05-06-28').click()
  await page.getByTestId('create-popover-more').click()
  const editor = page.getByRole('dialog', { name: 'New event' })
  const title = `Design review ${Date.now()}`
  await editor.getByTestId('event-title').fill(title)
  await expect(editor.getByTestId('event-start-time')).toHaveValue('14:00')
  await editor.getByTestId('event-end-time').fill('15:30')
  const registration = page.waitForRequest((sent) => sent.method() === 'POST' && new URL(sent.url()).pathname === '/api/v1/chat/call-links')
  await editor.getByTestId('event-meeting-add').click()
  const registered = (await registration).postData() ?? ''
  expect(registered).not.toContain('Design review')
  await expect(editor.getByTestId('event-meeting-link')).toHaveText('Kutup meeting')
  const link = await editor.getByTestId('event-meeting-join').getAttribute('href')
  expect(link).toMatch(new RegExp(`^${appUrl('chat', '/call#').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[A-Za-z0-9_-]{44}$`))
  expect(registered).not.toContain(link!.split('#')[1])
  const saved = page.waitForRequest((sent) => sent.method() === 'POST' && /\/events\/sync$/.test(new URL(sent.url()).pathname))
  await editor.getByTestId('event-save').click()
  // The link is in the encrypted part only: no part in the clear names it.
  const body = (await saved).postData() ?? ''
  expect(body).not.toContain(link!.split('#')[1])
  expect(body).not.toContain('CONFERENCE')
  await expect(page.getByText('Event created').last()).toBeVisible({ timeout: 30_000 })

  // Its details offer Join, to the same link.
  await page.getByTestId('calendar-event').filter({ hasText: title }).click()
  await expect(page.getByTestId('event-popover-meeting')).toContainText('Kutup meeting')
  await expect(page.getByTestId('event-popover-join')).toHaveAttribute('href', link!)
  await page.keyboard.press('Escape')

  // The meeting is the account's own, in Chat's list, at the event's time.
  const chat = await context.newPage()
  await chat.goto(appUrl('chat', '/meetings'))
  const row = chat.locator(`[data-testid="chat-meeting"][data-title="${title}"]`)
  await expect(row).toBeVisible({ timeout: 60_000 })
  await expect(row.getByTestId('chat-meeting-when')).toContainText('90 minutes')
  await expect(row.getByTestId('chat-meeting-url')).toHaveText(link!)

  // Chat's "Add to Kutup Calendar": the editor opens filled in, nothing saved
  // until the person saves.
  const opened = context.waitForEvent('page')
  await row.getByTestId('chat-meeting-calendar').click()
  const back = await opened
  const filled = back.getByRole('dialog', { name: 'New event' })
  await expect(filled.getByTestId('event-title')).toHaveValue(title, { timeout: 120_000 })
  await expect(filled.getByTestId('event-start-time')).toHaveValue('14:00')
  await expect(filled.getByTestId('event-end-time')).toHaveValue('15:30')
  await expect(filled.getByTestId('event-meeting-join')).toHaveAttribute('href', link!)
  // The link's secret doesn't stay in the address.
  expect(back.url()).not.toContain('#')
  await context.close()
})
