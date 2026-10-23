import i18next from 'i18next'
import { beforeAll, describe, expect, it } from 'vitest'
import en from '../../locales/en.json'
import { alarmText, alarmTitle } from './alarmText'

const i18n = i18next.createInstance()
beforeAll(async () => {
  await i18n.init({ lng: 'en', resources: { en: { translation: en } }, interpolation: { escapeValue: false } })
})

/** The text for an event at `start`, `now` on the same wall clock (24-hour, English). */
const text = (start: string, now: string, allDay = false) =>
  alarmText(i18n.t.bind(i18n), { title: 'Standup', allDay, start, now, locale: 'en-GB', hour12: false })

describe('a reminder’s words, as Proton’s', () => {
  it('says now within half a minute either way', () => {
    expect(text('2026-10-29T09:30:00', '2026-10-29T09:29:45')).toBe('Standup starts now')
    expect(text('2026-10-29T09:30:00', '2026-10-29T09:30:30')).toBe('Standup starts now')
  })

  it('says when it starts: today, tomorrow, this month, this year, later', () => {
    expect(text('2026-10-29T09:30:00', '2026-10-29T09:15:00')).toBe('Standup starts at 9:30')
    expect(text('2026-10-30T09:30:00', '2026-10-29T21:00:00')).toBe('Standup starts tomorrow at 9:30')
    expect(text('2026-10-31T09:30:00', '2026-10-29T09:00:00')).toBe('Standup starts on Saturday 31 at 9:30')
    expect(text('2026-11-02T09:30:00', '2026-10-29T09:00:00')).toBe('Standup starts on Monday 2 November at 9:30')
    expect(text('2027-01-04T09:30:00', '2026-10-29T09:00:00')).toBe('Standup starts on Monday, 4 January 2027 at 9:30')
  })

  it('says when it started, for a late one', () => {
    expect(text('2026-10-29T09:00:00', '2026-10-29T09:15:00')).toBe('Standup started at 9:00')
    expect(text('2026-10-28T23:30:00', '2026-10-29T00:10:00')).toBe('Standup started yesterday at 23:30')
  })

  it('says the day of an all-day event, never a time', () => {
    expect(text('2026-10-29', '2026-10-28T09:00:00', true)).toBe('Standup starts tomorrow')
    expect(text('2026-10-29', '2026-10-29T09:00:00', true)).toBe('Standup starts today')
    expect(text('2026-11-03', '2026-10-29T09:00:00', true)).toBe('Standup starts on Tuesday 3 November')
  })

  it('cuts a title to 100 characters and names an untitled one', () => {
    expect(alarmTitle('  ', '(no title)')).toBe('(no title)')
    expect(alarmTitle('x'.repeat(120), '(no title)')).toHaveLength(100)
  })
})
