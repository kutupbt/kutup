import { expect, test, type BrowserContext } from '../fixtures/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'

// `.ics` import and export (docs/plans/calendar.md, E2 §5–6), as Proton's:
// a Google-style export with a weekly series, a changed occurrence, a
// single event, an event whose rule Kutup can't take and a to-do is read in
// the browser; what can't be imported is listed before anything is sent;
// the rest is encrypted and added. The calendar exported (decrypted here)
// carries the series; imported again it overwrites the same events, never
// adding a second copy. Istanbul's time, weeks from Monday, a 24-hour clock.

const PASSWORD = 'Deneme123*CalendarIcsPassword'
const WEEK = '/?view=week&date=2026-11-02'

const FILE = [
  'BEGIN:VCALENDAR',
  'PRODID:-//Google Inc//Google Calendar 70.9054//EN',
  'VERSION:2.0',
  'CALSCALE:GREGORIAN',
  'METHOD:PUBLISH',
  'X-WR-CALNAME:Work',
  'X-WR-TIMEZONE:Europe/Istanbul',
  'BEGIN:VEVENT',
  'DTSTART;TZID=Europe/Istanbul:20261102T100000',
  'DTEND;TZID=Europe/Istanbul:20261102T103000',
  'RRULE:FREQ=WEEKLY;COUNT=4;BYDAY=MO',
  'EXDATE;TZID=Europe/Istanbul:20261116T100000',
  'DTSTAMP:20261101T120000Z',
  'UID:weekly-sync@e2e.example',
  'SEQUENCE:1',
  'SUMMARY:Team sync',
  'LOCATION:Room 4\\, Floor 2',
  'BEGIN:VALARM',
  'ACTION:DISPLAY',
  'TRIGGER:-PT10M',
  'END:VALARM',
  'END:VEVENT',
  'BEGIN:VEVENT',
  'DTSTART;TZID=Europe/Istanbul:20261109T140000',
  'DTEND;TZID=Europe/Istanbul:20261109T143000',
  'RECURRENCE-ID;TZID=Europe/Istanbul:20261109T100000',
  'DTSTAMP:20261101T120000Z',
  'UID:weekly-sync@e2e.example',
  'SUMMARY:Team sync (moved)',
  'END:VEVENT',
  'BEGIN:VEVENT',
  'DTSTART:20261104T090000Z',
  'DTEND:20261104T100000Z',
  'DTSTAMP:20261101T120000Z',
  'UID:lunch@e2e.example',
  'SUMMARY:Lunch with Deniz',
  'END:VEVENT',
  'BEGIN:VEVENT',
  'DTSTART;TZID=Europe/Istanbul:20261103T090000',
  'RRULE:FREQ=HOURLY;COUNT=3',
  'DTSTAMP:20261101T120000Z',
  'UID:hourly@e2e.example',
  'SUMMARY:Hourly check',
  'END:VEVENT',
  'BEGIN:VTODO',
  'UID:todo@e2e.example',
  'SUMMARY:Buy tickets',
  'END:VTODO',
  'END:VCALENDAR',
  '',
].join('\r\n')

async function istanbul(context: BrowserContext) {
  await context.addInitScript(() => {
    localStorage.setItem('kutup.calendar.prefs', JSON.stringify({ zone: 'Europe/Istanbul', weekStart: 1, hour12: false }))
  })
}

test('calendar: an .ics import reports what it can’t take, the export reads back, a second import overwrites', async ({ browser }) => {
  test.slow()
  const account = newAccount('calendar-ics', PASSWORD)
  const context = await browser.newContext({ acceptDownloads: true })
  await istanbul(context)
  await registerAccount(context, account)
  const page = await context.newPage()
  await page.goto(appUrl('calendar', WEEK))
  await expect(page.getByTestId('calendar-list-item').filter({ hasText: 'My calendar' })).toBeVisible({ timeout: 120_000 })

  // The file: refused by its type first, then read.
  await page.getByTestId('calendar-import').click()
  const dialog = page.getByTestId('import-dialog')
  await expect(dialog).toContainText('up to 15000 events')
  await dialog.getByTestId('import-file').setInputFiles({ name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('hello') })
  await expect(dialog.getByTestId('import-failure')).toContainText('Only ICS file formats are allowed')
  await dialog.getByTestId('import-file').setInputFiles({ name: 'work.ics', mimeType: 'text/calendar', buffer: Buffer.from(FILE) })
  await expect(dialog.getByTestId('import-file-name')).toHaveText('work.ics')
  await dialog.getByTestId('import-submit').click()

  // What can't be imported, with Proton's reasons, before anything is sent.
  await expect(dialog.getByTestId('import-partial')).toBeVisible({ timeout: 60_000 })
  await expect(page.getByRole('heading', { name: 'Continue with partial import?' })).toBeVisible()
  await dialog.getByTestId('import-errors').locator('summary').click()
  const errors = dialog.getByTestId('import-error')
  await expect(errors).toHaveCount(2)
  await expect(errors.filter({ hasText: 'hourly@e2e.example' })).toContainText('Recurring rule not supported')
  await expect(errors.filter({ hasText: 'todo@e2e.example' })).toContainText('To-do entry')
  await dialog.getByTestId('import-continue').click()
  await expect(dialog.getByTestId('import-done')).toContainText('Events successfully imported', { timeout: 120_000 })
  await expect(dialog.getByTestId('ics-progress')).toHaveText('3/3 events encrypted and added to your calendar')
  await dialog.getByTestId('import-close').click()

  // The events, in Istanbul's time: the series at its start, the single
  // event (written in UTC) in the calendar's zone, and the changed
  // occurrence where it moved.
  const monday = page.getByTestId('calendar-column-2026-11-02')
  await expect(monday.getByTestId('calendar-event').filter({ hasText: 'Team sync' })).toContainText('10:00', { timeout: 60_000 })
  await expect(page.getByTestId('calendar-column-2026-11-04').getByTestId('calendar-event').filter({ hasText: 'Lunch with Deniz' })).toContainText('12:00')
  await monday.getByTestId('calendar-event').filter({ hasText: 'Team sync' }).click()
  const editor = page.getByRole('dialog', { name: 'Event' })
  await expect(editor.getByLabel('Location')).toHaveValue('Room 4, Floor 2')
  await editor.getByRole('button', { name: 'Cancel' }).click()
  await page.goto(appUrl('calendar', '/?view=week&date=2026-11-09'))
  await expect(page.getByTestId('calendar-column-2026-11-09').getByTestId('calendar-event').filter({ hasText: 'Team sync (moved)' })).toContainText('14:00', {
    timeout: 60_000,
  })
  await page.goto(appUrl('calendar', WEEK))

  // The export: every event opened here and written as one file.
  await page.getByRole('button', { name: 'Edit My calendar' }).click({ force: true })
  await page.getByTestId('calendar-export').click()
  const exporting = page.getByTestId('export-dialog')
  await expect(exporting.getByTestId('export-summary')).toContainText('All 3 events have been successfully exported', { timeout: 60_000 })
  const download = page.waitForEvent('download')
  await exporting.getByTestId('export-save').click()
  const saved = await download
  expect(saved.suggestedFilename()).toMatch(/^My calendar-\d{4}-\d{2}-\d{2}\.ics$/)
  const exported = await (await saved.createReadStream()).toArray().then((chunks) => Buffer.concat(chunks).toString('utf8'))
  expect(exported).toContain('X-WR-CALNAME:My calendar')
  expect(exported).toContain('BEGIN:VTIMEZONE\r\nTZID:Europe/Istanbul')
  expect(exported).toContain('RRULE:FREQ=WEEKLY;COUNT=4;BYDAY=MO')
  expect(exported).toContain('EXDATE;TZID=Europe/Istanbul:20261116T100000')
  expect(exported).toContain('RECURRENCE-ID;TZID=Europe/Istanbul:20261109T100000')
  expect(exported).toContain('BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT10M\r\nDESCRIPTION:Team sync')
  expect(exported).not.toContain('Hourly check')

  // Imported again: the same events written over, no second copy.
  await page.getByTestId('calendar-import').click()
  const again = page.getByTestId('import-dialog')
  await again.getByTestId('import-file').setInputFiles({ name: saved.suggestedFilename(), mimeType: 'text/calendar', buffer: Buffer.from(exported) })
  await again.getByTestId('import-submit').click()
  await expect(again.getByTestId('import-done')).toContainText('Events successfully imported', { timeout: 120_000 })
  await again.getByTestId('import-close').click()
  await page.reload()
  await expect(monday.getByTestId('calendar-event').filter({ hasText: 'Team sync' })).toHaveCount(1, { timeout: 60_000 })
  await expect(page.getByTestId('calendar-column-2026-11-04').getByTestId('calendar-event').filter({ hasText: 'Lunch with Deniz' })).toHaveCount(1)
  await context.close()
})
