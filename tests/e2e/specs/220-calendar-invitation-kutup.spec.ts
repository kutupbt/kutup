import { expect, test, type Page } from '../fixtures/test'
import { appUrl } from '../fixtures/apps'
import { calendarAccount, eventsToday, openWeek, today } from '../fixtures/calendar'
import { openWhenArrived } from '../fixtures/mail'

// Calendar invitations between Kutup users of one server
// (docs/plans/calendar-e4.md §4–6, Proton's AddedProtonAttendees): Ada
// invites Bea from the event editor; the event appears in Bea's calendar at
// once ("Add to calendar and mark as pending", on by default), and the
// invitation reaches her Mail. Bea answers Yes from the event view; Ada sees
// the answer. Ada's change reaches Bea's calendar and Mail as an update, her
// delete as a cancellation.

const PASSWORD = 'Deneme123*CalendarInvitationPassword'

async function newEventWith(page: Page, hour: number, title: string, participant: string) {
  await page.getByTestId(`calendar-slot-${today()}-${hour * 2}`).click()
  await page.getByTestId('create-popover-more').click()
  const editor = page.getByRole('dialog', { name: 'New event' })
  await editor.getByLabel('Title').fill(title)
  await editor.getByTestId('event-participant-input').fill(participant)
  await editor.getByTestId('event-participant-add').click()
  await expect(editor.getByTestId('event-participant')).toContainText(participant)
  await editor.getByRole('button', { name: 'Save' }).click()
  await expect(editor).toBeHidden({ timeout: 60_000 })
}

async function openPopover(page: Page, title: string) {
  await eventsToday(page).filter({ hasText: title }).first().click()
  const popover = page.getByTestId('event-popover')
  await expect(popover).toBeVisible()
  return popover
}

test('calendar invitations: a Kutup attendee gets the event at once, answers it, sees its update and cancellation', async ({ browser }) => {
  test.slow()
  const ada = await calendarAccount(browser, 'calinvada', PASSWORD)
  const bea = await calendarAccount(browser, 'calinvbea', PASSWORD)

  // Ada invites Bea.
  await newEventWith(ada.page, 10, 'Plan the trip', bea.account.address)
  await expect(eventsToday(ada.page).filter({ hasText: 'Plan the trip' })).toBeVisible({ timeout: 30_000 })

  // It is in Bea's calendar without a mail opened, not answered yet.
  await expect(async () => {
    await openWeek(bea.page)
    await expect(eventsToday(bea.page).filter({ hasText: 'Plan the trip' })).toBeVisible({ timeout: 5_000 })
  }).toPass({ timeout: 90_000 })
  const peek = await openPopover(bea.page, 'Plan the trip')
  await expect(peek.getByTestId('event-popover-organizer')).toContainText(ada.account.address)
  await expect(peek.getByTestId('event-popover-edit')).toHaveCount(0)
  const mine = peek.getByTestId('event-attendee').filter({ hasText: bea.account.address })
  await expect(mine).toHaveAttribute('data-partstat', 'needs-action', { timeout: 30_000 })

  // Bea answers Yes from the event view.
  await peek.getByTestId('event-rsvp-accepted').click()
  await expect(bea.page.getByText('Answer sent')).toBeVisible({ timeout: 60_000 })

  // Ada sees the answer on her event.
  await expect(async () => {
    await openWeek(ada.page)
    const own = await openPopover(ada.page, 'Plan the trip')
    await expect(own.getByTestId('event-attendee').filter({ hasText: bea.account.address })).toHaveAttribute('data-partstat', 'accepted', { timeout: 5_000 })
  }).toPass({ timeout: 90_000 })
  await ada.page.keyboard.press('Escape')

  // Bea's Mail has the invitation, its widget showing her answer.
  const mail = await bea.context.newPage()
  await mail.goto(appUrl('mail', '/'))
  await openWhenArrived(mail, /Invitation for an event starting on/)
  const widget = mail.getByTestId('invitation-widget')
  await expect(widget.getByTestId('invitation-title')).toHaveText('Plan the trip', { timeout: 60_000 })
  await expect(widget.getByTestId('invitation-status')).toHaveAttribute('data-answer', 'accepted', { timeout: 60_000 })

  // Ada renames it: Bea's copy follows, and the update reaches her Mail.
  await openPopover(ada.page, 'Plan the trip').then((p) => p.getByTestId('event-popover-edit').click())
  const editor = ada.page.getByRole('dialog', { name: 'Event' })
  await editor.getByLabel('Title').fill('Plan the trip, v2')
  await editor.getByRole('button', { name: 'Save' }).click()
  await expect(editor).toBeHidden({ timeout: 60_000 })
  await expect(async () => {
    await openWeek(bea.page)
    await expect(eventsToday(bea.page).filter({ hasText: 'Plan the trip, v2' })).toBeVisible({ timeout: 5_000 })
  }).toPass({ timeout: 90_000 })
  // A new title moved nothing: Bea's answer stands (only a new time asks again).
  await openWeek(ada.page)
  const renamed = await openPopover(ada.page, 'Plan the trip, v2')
  await expect(renamed.getByTestId('event-attendee').filter({ hasText: bea.account.address })).toHaveAttribute('data-partstat', 'accepted', { timeout: 30_000 })
  await ada.page.keyboard.press('Escape')
  await openWhenArrived(mail, /Update for an event starting on/)
  await expect(mail.getByTestId('invitation-widget').getByTestId('invitation-title')).toHaveText('Plan the trip, v2', { timeout: 60_000 })

  // Ada deletes it: gone from Bea's calendar, the cancellation in her Mail.
  await openPopover(ada.page, 'Plan the trip, v2').then((p) => p.getByTestId('event-popover-delete').click())
  await ada.page.getByRole('button', { name: 'Delete event' }).last().click()
  await expect(eventsToday(ada.page).filter({ hasText: 'Plan the trip, v2' })).toHaveCount(0, { timeout: 60_000 })
  await expect(async () => {
    await openWeek(bea.page)
    await expect(eventsToday(bea.page).filter({ hasText: 'Plan the trip, v2' })).toHaveCount(0, { timeout: 5_000 })
  }).toPass({ timeout: 90_000 })
  await openWhenArrived(mail, /Cancellation of an event starting on/)
  await expect(mail.getByTestId('invitation-widget').getByTestId('invitation-status')).toHaveAttribute('data-status', 'cancelled', { timeout: 60_000 })

  await ada.context.close()
  await bea.context.close()
})
