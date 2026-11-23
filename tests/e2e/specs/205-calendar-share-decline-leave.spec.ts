import { expect, test } from '../fixtures/test'
import { execSync } from 'node:child_process'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { calendarAccount, invite, istanbulContext, joinFrom, openSharing, openWeek } from '../fixtures/calendar'

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

// A due key change to someone the owner never met (here a member the
// database slipped in, as a server could) is never made unasked: the row
// says a key change is pending, and the dialog names who would get the new
// key, as the pins see them, before the owner confirms.
test('calendar sharing: a due key change to someone never met waits for the owner to review it', async ({ browser }) => {
  test.slow()
  const psql = process.env.E2E_PSQL
  test.skip(!psql, 'E2E_PSQL: a command that runs SQL from its stdin against the test stack database')
  const ada = await calendarAccount(browser, 'calrevada', PASSWORD, 'Pond')
  const bob = await calendarAccount(browser, 'calrevbob', PASSWORD)
  const dan = newAccount('calrevdan', PASSWORD)
  const danContext = await istanbulContext(browser)
  await registerAccount(danContext, dan)
  const sharing = await openSharing(ada.page, 'Pond')
  await invite(ada.page, sharing, bob.account.address, 'See all event details')
  await ada.page.keyboard.press('Escape')
  await openWeek(bob.page)
  await joinFrom(bob.page, ada.account, 'Pond')

  // The database adds Dan as a member; then Bob leaves, so a key change is due.
  execSync(psql!, {
    input: `INSERT INTO calendar_members (calendar_id, account_id, permissions)
              SELECT c.id, d.id, 96 FROM calendars c JOIN accounts a ON a.id = c.owner_account_id, accounts d
               WHERE a.username = '${ada.account.username}' AND d.username = '${dan.username}';\n`,
    encoding: 'utf8',
  })
  await bob.page.getByRole('button', { name: 'Edit Pond' }).click()
  await bob.page.getByRole('dialog', { name: 'Calendar' }).getByTestId('calendar-leave').click()
  await bob.page.getByRole('button', { name: 'Leave calendar' }).last().click()
  await expect(bob.page.getByText('You left Pond').last()).toBeVisible({ timeout: 30_000 })

  // Ada's app doesn't rotate on its own: it asks.
  await openWeek(ada.page)
  const pending = ada.page.getByTestId('rotation-pending')
  await expect(pending).toHaveText('Key change pending — review', { timeout: 60_000 })
  await pending.click()
  const dialog = ada.page.getByTestId('due-rotation')
  const dans = dialog.getByTestId('key-recipient').filter({ hasText: dan.address })
  await expect(dans).toContainText('First time', { timeout: 60_000 })
  await expect(dialog.getByTestId('key-recipients')).not.toContainText(bob.account.address)
  await expect(dialog.getByText('Not everyone here is someone you already know.', { exact: false })).toBeVisible()
  await dialog.getByTestId('due-rotation-confirm').click()
  await expect(ada.page.getByText('The key of Pond was changed').last()).toBeVisible({ timeout: 60_000 })
  await expect(pending).toHaveCount(0)
  await openWeek(ada.page)
  await expect(ada.page.getByTestId('calendar-list-item').filter({ hasText: 'Pond' })).toBeVisible()
  await expect(ada.page.getByTestId('rotation-pending')).toHaveCount(0)
  await danContext.close()
  await ada.context.close()
  await bob.context.close()
})
