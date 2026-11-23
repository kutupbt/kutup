import { expect, test } from '../fixtures/test'
import { addEvent, calendarAccount, eventsToday, invite, istanbulContext, joinFrom, openSharing, openWeek } from '../fixtures/calendar'

// Removing a member rotates the calendar's key (docs/plans/calendar-e3.md
// §2): a new generation, shared with everyone who stays, the name sealed
// again, in one request. The dialog says who gets the new key, and replaces
// the calendar's keyed links by default (the old addresses stop working, the
// owner gets new ones). The removed member no longer has the calendar; the
// one who stays reads both the old events and those written after.

const PASSWORD = 'Deneme123*CalendarRemovePassword'

test('calendar sharing: removing a member makes a new key, the others keep reading', async ({ browser }) => {
  test.slow()
  const ada = await calendarAccount(browser, 'calrmada', PASSWORD, 'Club')
  await addEvent(ada.page, 9, 'Before the removal')
  const bob = await calendarAccount(browser, 'calrmbob', PASSWORD)
  const cem = await calendarAccount(browser, 'calrmcem', PASSWORD)

  const sharing = await openSharing(ada.page, 'Club')
  await invite(ada.page, sharing, bob.account.address, 'See all event details')
  await invite(ada.page, sharing, cem.account.address, 'See all event details')
  await ada.page.keyboard.press('Escape')
  for (const member of [bob, cem]) {
    await openWeek(member.page)
    await joinFrom(member.page, ada.account, 'Club')
    await expect(eventsToday(member.page).filter({ hasText: 'Before the removal' })).toBeVisible({ timeout: 60_000 })
  }

  // A full link Bob may have seen.
  await openWeek(ada.page)
  let again = await openSharing(ada.page, 'Club')
  await again.getByRole('tab', { name: 'Links' }).click()
  await again.getByTestId('link-create').click()
  const linkDialog = ada.page.getByTestId('link-dialog')
  await linkDialog.getByTestId('link-kind-full').check()
  await linkDialog.getByTestId('link-create-submit').click()
  const oldUrl = await linkDialog.getByTestId('link-url-page').inputValue({ timeout: 60_000 })
  await linkDialog.getByRole('button', { name: 'Done' }).click()
  await ada.page.keyboard.press('Escape')

  // Bob is removed: the dialog names who gets the new key (Cem) and the
  // link, replaced by default.
  await openWeek(ada.page)
  again = await openSharing(ada.page, 'Club')
  await again.getByRole('button', { name: `Remove ${bob.account.address}` }).click()
  const recipients = ada.page.getByTestId('remove-recipients')
  await expect(recipients).toContainText(cem.account.address, { timeout: 60_000 })
  await expect(recipients).not.toContainText(bob.account.address)
  await expect(ada.page.getByTestId('remove-links')).toContainText('All event details')
  await expect(ada.page.getByTestId('remove-replace-links')).toBeChecked()
  await ada.page.getByRole('button', { name: 'Remove', exact: true }).click()
  const replaced = ada.page.getByTestId('replaced-links')
  const newUrl = await replaced.getByTestId('replaced-0-url-page').inputValue({ timeout: 60_000 })
  expect(newUrl).not.toBe(oldUrl)
  await replaced.getByRole('button', { name: 'Done' }).click()
  await expect(ada.page.getByText(`${bob.account.address} was removed`).last()).toBeVisible({ timeout: 60_000 })
  await expect(again.getByTestId('share-members')).not.toContainText(bob.account.address, { timeout: 30_000 })
  await ada.page.keyboard.press('Escape')

  // Ada writes under the new key; Cem reads the old event and the new one.
  await openWeek(ada.page)
  await addEvent(ada.page, 15, 'After the removal')
  await openWeek(cem.page)
  await expect(eventsToday(cem.page).filter({ hasText: 'Before the removal' })).toBeVisible({ timeout: 60_000 })
  await expect(eventsToday(cem.page).filter({ hasText: 'After the removal' })).toBeVisible({ timeout: 60_000 })

  // The old link opens nothing; the new one opens the calendar, both
  // generations' events.
  const visitor = await istanbulContext(browser)
  const page = await visitor.newPage()
  await page.goto(oldUrl)
  await expect(page.getByText("This link doesn't work any more")).toBeVisible({ timeout: 60_000 })
  await page.goto('about:blank')
  await page.goto(newUrl)
  const opened = page.getByTestId('public-calendar')
  await expect(opened.getByTestId('public-item').filter({ hasText: 'Before the removal' })).toBeVisible({ timeout: 60_000 })
  await expect(opened.getByTestId('public-item').filter({ hasText: 'After the removal' })).toBeVisible()
  await visitor.close()

  // Bob no longer has the calendar, nor anything written after.
  await openWeek(bob.page)
  await expect(bob.page.getByTestId('calendar-list-item').filter({ hasText: 'Club' })).toHaveCount(0, { timeout: 60_000 })
  await expect(eventsToday(bob.page).filter({ hasText: 'After the removal' })).toHaveCount(0)
  for (const member of [ada, bob, cem]) await member.context.close()
})
