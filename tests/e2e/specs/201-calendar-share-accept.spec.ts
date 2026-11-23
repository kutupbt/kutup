import { expect, test } from '../fixtures/test'
import { addEvent, calendarAccount, eventsToday, invite, joinFrom, openSharing, openWeek } from '../fixtures/calendar'

// Calendar sharing (docs/plans/calendar-e3.md §1, E3c): the owner invites a
// person of this server by address with Proton's edit preset; the invitee
// opens the invitation from "Shared with you", the owner checked against
// its pins, and joins. Both then see and write the same events, each sealed
// to the calendar key, with the owner paying for them.

const PASSWORD = 'Deneme123*CalendarSharePassword'

test('calendar sharing: an invitation with the edit preset, joined; both read and write its events', async ({ browser }) => {
  test.slow()
  const ada = await calendarAccount(browser, 'calshareada', PASSWORD, 'Family')
  await addEvent(ada.page, 9, 'Breakfast together')
  const bob = await calendarAccount(browser, 'calsharebob', PASSWORD)

  const sharing = await openSharing(ada.page, 'Family')
  await invite(ada.page, sharing, bob.account.address, 'Edit event details')
  await expect(sharing.getByTestId('share-members')).toContainText('Invitation sent')
  await ada.page.keyboard.press('Escape')

  // Bob joins: the calendar is listed beside his own, its event opens.
  await openWeek(bob.page)
  await joinFrom(bob.page, ada.account, 'Family')
  await expect(eventsToday(bob.page).filter({ hasText: 'Breakfast together' })).toBeVisible({ timeout: 60_000 })

  // He writes into it; Ada sees his event after a reload.
  await addEvent(bob.page, 13, 'Lunch by Bob', 'Family')
  await openWeek(ada.page)
  await expect(eventsToday(ada.page).filter({ hasText: 'Lunch by Bob' })).toBeVisible({ timeout: 60_000 })

  // On Ada's side he is a member now, with the edit preset.
  const again = await openSharing(ada.page, 'Family')
  await expect(again.getByRole('combobox', { name: `What ${bob.account.address} can do` })).toHaveText('Edit event details', { timeout: 30_000 })
  await ada.context.close()
  await bob.context.close()
})
