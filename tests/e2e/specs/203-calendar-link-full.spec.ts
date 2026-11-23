import { expect, test } from '../fixtures/test'
import { addEvent, calendarAccount, istanbulContext, openSharing } from '../fixtures/calendar'

// A full link (docs/plans/calendar-e3.md §3): the calendar's key in the
// URL's fragment, which never reaches the server; anyone with the link sees
// the week's events in the browser, without an account. Deleted, it opens
// nothing.

const PASSWORD = 'Deneme123*CalendarLinkPassword'

test('calendar links: a full link opens the events without an account, and stops when deleted', async ({ browser }) => {
  test.slow()
  const ada = await calendarAccount(browser, 'callinkada', PASSWORD, 'Choir')
  await addEvent(ada.page, 18, 'Rehearsal')

  const sharing = await openSharing(ada.page, 'Choir')
  await sharing.getByRole('tab', { name: 'Links' }).click()
  await sharing.getByTestId('link-create').click()
  const dialog = ada.page.getByTestId('link-dialog')
  await dialog.getByTestId('link-kind-full').check()
  await dialog.getByTestId('link-label').fill('For the choir')
  await dialog.getByTestId('link-create-submit').click()
  const url = await dialog.getByTestId('link-url-page').inputValue({ timeout: 60_000 })
  expect(url).toMatch(/\/l\/[0-9a-f-]+#.+/)
  await dialog.getByRole('button', { name: 'Done' }).click()
  await expect(sharing.getByTestId('calendar-links')).toContainText('For the choir', { timeout: 30_000 })

  // Anyone with the link: the name and the event, opened here.
  const visitor = await istanbulContext(browser)
  const page = await visitor.newPage()
  await page.goto(url)
  const opened = page.getByTestId('public-calendar')
  await expect(opened).toContainText('Choir', { timeout: 60_000 })
  await expect(opened.getByTestId('public-item').filter({ hasText: 'Rehearsal' })).toBeVisible()

  // The link's id alone opens nothing: without the proof its secret gives,
  // the server tells only the kind, and serves no events.
  const linkId = url.replace(/.*\/l\/([^#]+)#.*/, '$1')
  const bare = await visitor.request.get(url.replace(/\/l\/.*/, `/api/v1/calendar/links/${linkId}`))
  expect(await bare.json()).toEqual({ calendarId: null, kind: 'full', metadata: null, keys: null })
  const events = await visitor.request.get(url.replace(/\/l\/.*/, `/api/v1/calendar/links/${linkId}/events?start=2026-01-01T00:00:00Z&end=2026-02-01T00:00:00Z`))
  expect(events.status()).toBe(404)
  const busy = await visitor.request.get(url.replace(/\/l\/.*/, `/api/v1/calendar/links/${linkId}/busy?start=2026-01-01T00:00:00Z&end=2026-02-01T00:00:00Z`))
  expect(busy.status()).toBe(404)

  // Without its fragment, the link says it is incomplete.
  await page.goto(url.replace(/#.*/, ''))
  await expect(page.getByText('This link is incomplete')).toBeVisible({ timeout: 60_000 })

  // Deleted: gone for everyone.
  await sharing.getByRole('button', { name: 'Delete link' }).click()
  await ada.page.getByRole('button', { name: 'Delete link' }).last().click()
  await expect(ada.page.getByText('Link deleted').last()).toBeVisible({ timeout: 30_000 })
  // A fresh load (from the address without its fragment, only the
  // fragment would change and the page would not load again).
  await page.goto('about:blank')
  await page.goto(url)
  await expect(page.getByText("This link doesn't work any more")).toBeVisible({ timeout: 60_000 })
  await visitor.close()
  await ada.context.close()
})
