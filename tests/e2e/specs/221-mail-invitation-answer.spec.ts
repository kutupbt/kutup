import { expect, test } from '../fixtures/test'
import { appUrl } from '../fixtures/apps'
import { calendarAccount, eventsToday, openWeek, today } from '../fixtures/calendar'
import { openWhenArrived } from '../fixtures/mail'

// Mail's invitation widget (docs/plans/calendar-e4.md §5, Proton's
// ExtraEvents): with "Add to calendar and mark as pending" off, an
// invitation waits in Mail; Bea answers Maybe there with a note, which
// puts it in her calendar and writes her answer; Ada's Mail gets the
// reply, its widget naming the answer, and her event shows it. The
// invitation and the reply go in the language each account sends in.

const PASSWORD = 'Deneme123*MailInvitationPassword'

test('mail invitations: answered from the widget, the reply read by the organizer', async ({ browser }) => {
  test.slow()
  const ada = await calendarAccount(browser, 'mailinvada', PASSWORD)
  const bea = await calendarAccount(browser, 'mailinvbea', PASSWORD)

  // Bea turns off "Add to calendar and mark as pending".
  await bea.page.getByRole('button', { name: 'Settings' }).first().click()
  const settings = bea.page.getByRole('dialog', { name: 'Settings' })
  await settings.getByTestId('settings-auto-add').click()
  await expect(bea.page.getByText('Preference saved')).toBeVisible({ timeout: 30_000 })
  await bea.page.keyboard.press('Escape')

  // Ada invites her.
  await ada.page.getByTestId(`calendar-slot-${today()}-${15 * 2}`).click()
  await ada.page.getByTestId('create-popover-more').click()
  const editor = ada.page.getByRole('dialog', { name: 'New event' })
  await editor.getByLabel('Title').fill('Budget review')
  await editor.getByTestId('event-participant-input').fill(bea.account.address)
  await editor.getByTestId('event-participant-add').click()
  await editor.getByRole('button', { name: 'Save' }).click()
  await expect(editor).toBeHidden({ timeout: 60_000 })

  // Bea's calendar doesn't hold it yet; her Mail does.
  await openWeek(bea.page)
  await expect(eventsToday(bea.page).filter({ hasText: 'Budget review' })).toHaveCount(0)
  const mail = await bea.context.newPage()
  await mail.goto(appUrl('mail', '/'))
  await openWhenArrived(mail, /Invitation for an event starting on/)
  const widget = mail.getByTestId('invitation-widget')
  await expect(widget.getByTestId('invitation-status')).toHaveAttribute('data-status', 'new', { timeout: 60_000 })
  await widget.getByTestId('invitation-note').fill('Ten minutes late')
  await widget.getByTestId('invitation-rsvp-tentative').click()
  await expect(mail.getByText('Answer sent')).toBeVisible({ timeout: 60_000 })
  await expect(widget.getByTestId('invitation-status')).toHaveAttribute('data-answer', 'tentative', { timeout: 60_000 })

  // Now in her calendar.
  await openWeek(bea.page)
  await expect(eventsToday(bea.page).filter({ hasText: 'Budget review' })).toBeVisible({ timeout: 60_000 })

  // Ada's Mail: the reply, its widget naming Bea's answer.
  const adaMail = await ada.context.newPage()
  await adaMail.goto(appUrl('mail', '/'))
  await openWhenArrived(adaMail, /^.*Re: Invitation for an event starting on/)
  const reply = adaMail.getByTestId('invitation-widget').getByTestId('invitation-reply')
  await expect(reply).toContainText('tentatively accepted your invitation', { timeout: 60_000 })
  await expect(adaMail.getByText('Ten minutes late')).toBeVisible()

  // And her event shows it.
  await openWeek(ada.page)
  await eventsToday(ada.page).filter({ hasText: 'Budget review' }).first().click()
  await expect(ada.page.getByTestId('event-popover').getByTestId('event-attendee').filter({ hasText: bea.account.address })).toHaveAttribute('data-partstat', 'tentative', { timeout: 60_000 })

  await ada.context.close()
  await bea.context.close()
})
