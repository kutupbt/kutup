import { expect, test } from '../fixtures/test'
import { addEvent, calendarAccount, eventsToday, invite, joinFrom, openSharing, openWeek } from '../fixtures/calendar'

// Removing a member rotates the calendar's key (docs/plans/calendar-e3.md
// §2): a new generation, shared with everyone who stays, the name sealed
// again, in one request. The removed member no longer has the calendar; the
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

  // Bob is removed: a new key for Ada and Cem.
  await openWeek(ada.page)
  const again = await openSharing(ada.page, 'Club')
  await again.getByRole('button', { name: `Remove ${bob.account.address}` }).click()
  await ada.page.getByRole('button', { name: 'Remove', exact: true }).click()
  await expect(ada.page.getByText(`${bob.account.address} was removed`).last()).toBeVisible({ timeout: 60_000 })
  await expect(again.getByTestId('share-members')).not.toContainText(bob.account.address, { timeout: 30_000 })
  await ada.page.keyboard.press('Escape')

  // Ada writes under the new key; Cem reads the old event and the new one.
  await openWeek(ada.page)
  await addEvent(ada.page, 15, 'After the removal')
  await openWeek(cem.page)
  await expect(eventsToday(cem.page).filter({ hasText: 'Before the removal' })).toBeVisible({ timeout: 60_000 })
  await expect(eventsToday(cem.page).filter({ hasText: 'After the removal' })).toBeVisible({ timeout: 60_000 })

  // Bob no longer has the calendar, nor anything written after.
  await openWeek(bob.page)
  await expect(bob.page.getByTestId('calendar-list-item').filter({ hasText: 'Club' })).toHaveCount(0, { timeout: 60_000 })
  await expect(eventsToday(bob.page).filter({ hasText: 'After the removal' })).toHaveCount(0)
  for (const member of [ada, bob, cem]) await member.context.close()
})
