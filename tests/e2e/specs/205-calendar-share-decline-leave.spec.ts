import { expect, test } from '../fixtures/test'
import { appUrl } from '../fixtures/apps'
import { calendarAccount, invite, joinFrom, openSharing, openWeek } from '../fixtures/calendar'

// The other ends of an invitation (docs/plans/calendar-e3.md §1): declined,
// the owner sees it and deletes it; revoked, it leaves the invitee's list;
// joined, the member may leave again (and can't show the owner's busy
// times). Someone who read the key and went makes the calendar due a
// rotation, which the owner's app makes when it next loads it.

const PASSWORD = 'Deneme123*CalendarDeclinePassword'

test('calendar sharing: declined, revoked, and a member who leaves', async ({ browser }) => {
  test.slow()
  const ada = await calendarAccount(browser, 'caldecada', PASSWORD, 'Garden')
  const bob = await calendarAccount(browser, 'caldecbob', PASSWORD)
  const sharing = await openSharing(ada.page, 'Garden')
  await invite(ada.page, sharing, bob.account.address, 'See all event details')
  await ada.page.keyboard.press('Escape')

  // Bob declines.
  await openWeek(bob.page)
  const row = bob.page.getByTestId('calendar-invitation').filter({ hasText: ada.account.address })
  await row.click()
  const dialog = bob.page.getByTestId('invitation-dialog')
  await expect(dialog.getByRole('heading', { name: 'Join Garden' })).toBeVisible({ timeout: 60_000 })
  await dialog.getByTestId('invitation-decline').click()
  await expect(bob.page.getByText('Invitation declined').last()).toBeVisible({ timeout: 30_000 })
  await expect(row).toHaveCount(0, { timeout: 30_000 })

  // Ada sees it declined, deletes it, and invites him again; she revokes
  // that one, and it leaves his list.
  await openWeek(ada.page)
  let again = await openSharing(ada.page, 'Garden')
  await expect(again.getByTestId('share-members')).toContainText('Declined', { timeout: 30_000 })
  await again.getByRole('button', { name: `Delete the declined invitation of ${bob.account.address}` }).click()
  await expect(ada.page.getByText('Invitation deleted').last()).toBeVisible({ timeout: 30_000 })
  await invite(ada.page, again, bob.account.address, 'See all event details')
  await again.getByRole('button', { name: `Revoke the invitation to ${bob.account.address}` }).click()
  await expect(ada.page.getByText('Invitation revoked').last()).toBeVisible({ timeout: 30_000 })
  await openWeek(bob.page)
  await expect(bob.page.getByTestId('calendar-invitation')).toHaveCount(0, { timeout: 30_000 })

  // A third invitation, joined, then left.
  await ada.page.keyboard.press('Escape')
  again = await openSharing(ada.page, 'Garden')
  await invite(ada.page, again, bob.account.address, 'See all event details')
  await openWeek(bob.page)
  await joinFrom(bob.page, ada.account, 'Garden')
  await bob.page.getByRole('button', { name: 'Edit Garden' }).click()
  const settings = bob.page.getByRole('dialog', { name: 'Calendar' })
  await expect(settings.getByText(`Shared with you by ${ada.account.address}.`)).toBeVisible()
  // Busy times are the owner's to show: no switch for a member.
  await expect(settings.getByTestId('calendar-share-busy')).toHaveCount(0)
  await settings.getByTestId('calendar-leave').click()
  await bob.page.getByRole('button', { name: 'Leave calendar' }).last().click()
  await expect(bob.page.getByText('You left Garden').last()).toBeVisible({ timeout: 30_000 })
  await expect(bob.page.getByTestId('calendar-list-item').filter({ hasText: 'Garden' })).toHaveCount(0, { timeout: 30_000 })

  // Ada's list no longer has him.
  await ada.page.keyboard.press('Escape')
  await openWeek(ada.page)
  const last = await openSharing(ada.page, 'Garden')
  await expect(last.getByText('Not shared with anyone yet.')).toBeVisible({ timeout: 30_000 })

  // Bob held the key: loading the calendar, Ada's app rotated it (one more
  // generation, nothing due), as it does after a removal.
  const tab = await ada.context.newPage()
  await tab.goto(appUrl('account', '/'))
  await expect
    .poll(
      () =>
        tab.evaluate(async () => {
          const refreshed = await fetch('/api/v1/auth/refresh', { method: 'POST', credentials: 'include' })
          const { accessToken } = (await refreshed.json()) as { accessToken: string }
          const headers = { Authorization: `Bearer ${accessToken}` }
          const { calendars } = (await (await fetch('/api/v1/calendar/calendars', { headers })).json()) as {
            calendars: { rotationDue: boolean; keyGeneration: number }[]
          }
          return calendars.length === 1 && calendars[0].keyGeneration >= 2 && !calendars[0].rotationDue
        }),
      { timeout: 120_000 },
    )
    .toBe(true)
  await tab.close()
  await ada.context.close()
  await bob.context.close()
})
