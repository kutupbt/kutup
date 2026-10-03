import { describe, expect, it } from 'vitest'
import { defaultStart, fromLocalDateTime, isUpcoming, localDateTime, meetingStartText } from './meetingTime'

describe('meeting times', () => {
  it('round-trips a date and time through the form inputs', () => {
    const at = new Date(2026, 9, 6, 14, 30).getTime()
    const { date, time } = localDateTime(at)
    expect(date).toBe('2026-10-06')
    expect(time).toBe('14:30')
    expect(fromLocalDateTime(date, time)).toBe(at)
  })

  it('refuses an incomplete date or time', () => {
    expect(fromLocalDateTime('', '14:30')).toBeNull()
    expect(fromLocalDateTime('2026-10-06', '')).toBeNull()
    expect(fromLocalDateTime('06/10/2026', '14:30')).toBeNull()
  })

  it('counts a meeting as upcoming until its planned end', () => {
    const start = 1_800_000_000_000
    expect(isUpcoming({ title: 'a', startsAtMs: start, durationMinutes: 30 }, start - 1)).toBe(true)
    expect(isUpcoming({ title: 'a', startsAtMs: start, durationMinutes: 30 }, start + 29 * 60_000)).toBe(true)
    expect(isUpcoming({ title: 'a', startsAtMs: start, durationMinutes: 30 }, start + 31 * 60_000)).toBe(false)
    // Without a set length, an hour.
    expect(isUpcoming({ title: 'a', startsAtMs: start }, start + 59 * 60_000)).toBe(true)
    expect(isUpcoming({ title: 'a' }, start)).toBe(false)
  })

  it('names the year only when it is not this one', () => {
    const now = new Date(2026, 9, 3, 12, 0).getTime()
    expect(meetingStartText(new Date(2026, 9, 6, 14, 30).getTime(), 'en-US', now)).not.toContain('2026')
    expect(meetingStartText(new Date(2031, 4, 6, 14, 30).getTime(), 'en-US', now)).toContain('2031')
  })

  it('suggests the next quarter hour at least ten minutes away', () => {
    const base = new Date(2026, 9, 6, 14, 2).getTime()
    expect(new Date(defaultStart(base)).getMinutes()).toBe(15)
    const late = new Date(2026, 9, 6, 14, 8).getTime()
    expect(new Date(defaultStart(late)).getMinutes()).toBe(30)
  })
})
