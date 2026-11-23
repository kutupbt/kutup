import { expect, test } from '../fixtures/test'
import { addEvent, calendarAccount, istanbulContext, openSharing } from '../fixtures/calendar'

// Busy and feed links (docs/plans/calendar-e3.md §3): a busy link shows when
// its owner is busy, never what; a link for other calendar apps carries its
// key in the address, and the server opens the calendar on each fetch (the
// dialog says so).

const PASSWORD = 'Deneme123*CalendarFeedPassword'

test('calendar links: busy times only, and a feed for other calendar apps', async ({ browser }) => {
  test.slow()
  const ada = await calendarAccount(browser, 'calfeedada', PASSWORD, 'Office')
  await addEvent(ada.page, 10, 'Salary talk')
  const sharing = await openSharing(ada.page, 'Office')
  await sharing.getByRole('tab', { name: 'Links' }).click()
  const dialog = ada.page.getByTestId('link-dialog')

  // Busy times only.
  await sharing.getByTestId('link-create').click()
  await dialog.getByTestId('link-kind-busy').check()
  await dialog.getByTestId('link-create-submit').click()
  const busyUrl = await dialog.getByTestId('link-url-page').inputValue({ timeout: 60_000 })
  await dialog.getByRole('button', { name: 'Done' }).click()

  const visitor = await istanbulContext(browser)
  const page = await visitor.newPage()
  await page.goto(busyUrl)
  const opened = page.getByTestId('public-calendar')
  await expect(opened).toContainText('Busy times', { timeout: 60_000 })
  await expect(opened.getByTestId('public-item').filter({ hasText: 'Busy' })).toHaveCount(1)
  await expect(opened).not.toContainText('Salary talk')

  // A feed for other calendar apps: the warning first, then the address.
  await sharing.getByTestId('link-create').click()
  await dialog.getByTestId('link-kind-query').check()
  await expect(dialog.getByText('The server reads this calendar')).toBeVisible()
  await dialog.getByTestId('link-create-submit').click()
  const feedUrl = await dialog.getByTestId('link-url-ics').inputValue({ timeout: 60_000 })
  expect(feedUrl).toMatch(/\/calendar\.ics\?key=/)
  await dialog.getByRole('button', { name: 'Done' }).click()
  const feed = await visitor.request.get(feedUrl)
  expect(feed.status()).toBe(200)
  expect(feed.headers()['content-type']).toContain('text/calendar')
  const text = await feed.text()
  expect(text).toContain('SUMMARY:Salary talk')
  expect(text).toContain('X-WR-CALNAME:Office')
  // The busy link's feed: times only.
  const busyFeed = await visitor.request.get(busyUrl.replace('/l/', '/api/v1/calendar/links/') + '/calendar.ics')
  expect(busyFeed.status()).toBe(200)
  const busyText = await busyFeed.text()
  expect(busyText).toContain('SUMMARY:Busy')
  expect(busyText).not.toContain('Salary')
  // Another key opens nothing.
  const wrong = await visitor.request.get(feedUrl.replace(/key=.*/, 'key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'))
  expect(wrong.status()).toBe(404)
  await expect(sharing.getByTestId('calendar-links').locator('li')).toHaveCount(2)
  await visitor.close()
  await ada.context.close()
})
