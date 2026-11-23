import { expect, test } from '../fixtures/test'
import { appUrl } from '../fixtures/apps'
import { addEvent, calendarAccount, today } from '../fixtures/calendar'

// Busy times (docs/plans/calendar-e3.md §4, E3e): "Show others when I'm
// busy" is a calendar's own switch, off at first, kept on the server, which
// answers busy times from the readable times only — to the person and their
// organization, nobody else.

const PASSWORD = 'Deneme123*CalendarBusyPassword'

test('calendar busy times: the switch, kept, and what the server answers with it', async ({ browser }) => {
  test.slow()
  const ada = await calendarAccount(browser, 'calbusyada', PASSWORD, 'Work')
  await addEvent(ada.page, 11, 'Board meeting')

  await ada.page.getByRole('button', { name: 'Edit Work' }).click()
  const settings = ada.page.getByRole('dialog', { name: 'Calendar' })
  const share = settings.getByTestId('calendar-share-busy')
  await expect(share).not.toBeChecked()
  await share.check()
  await settings.getByTestId('calendar-save').click()
  await expect(settings).toBeHidden({ timeout: 30_000 })

  // Kept: after a reload it is still on.
  await ada.page.reload()
  await ada.page.getByRole('button', { name: 'Edit Work' }).click()
  await expect(ada.page.getByRole('dialog', { name: 'Calendar' }).getByTestId('calendar-share-busy')).toBeChecked({ timeout: 60_000 })
  await ada.page.keyboard.press('Escape')

  // The server's answer to her, asked in the account app's own tab (the
  // calendar tab's session is left alone): the block, never its title.
  const tab = await ada.context.newPage()
  await tab.goto(appUrl('account', '/'))
  const answer = await tab.evaluate(async (address) => {
    const refreshed = await fetch('/api/v1/auth/refresh', { method: 'POST', credentials: 'include' })
    if (!refreshed.ok) throw new Error(`refresh ${refreshed.status}`)
    const { accessToken } = (await refreshed.json()) as { accessToken: string }
    const start = new Date(Date.now() - 2 * 86_400_000).toISOString()
    const end = new Date(Date.now() + 2 * 86_400_000).toISOString()
    const response = await fetch(`/api/v1/calendar/busy?${new URLSearchParams({ address, start, end })}`, { headers: { Authorization: `Bearer ${accessToken}` } })
    return { status: response.status, body: await response.text() }
  }, ada.account.address)
  await tab.close()
  expect(answer.status).toBe(200)
  expect(answer.body).toContain(`"startUtc":"${today()}T08:00:00Z"`)
  expect(answer.body).not.toContain('Board meeting')
  await ada.context.close()
})
