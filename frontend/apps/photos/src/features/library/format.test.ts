import { describe, expect, it } from 'vitest'
import { formatDay, formatDuration, formatMonth, formatOffset, formatTaken } from './format'

describe('formatting', () => {
  it('names months and days without moving them across time zones', () => {
    expect(formatMonth('2024-07', 'en')).toBe('July 2024')
    expect(formatMonth('2024-07', 'tr')).toBe('Temmuz 2024')
    expect(formatDay('2024-07-01', 'en', new Date(2024, 5, 1))).toBe('Mon, July 1')
    expect(formatDay('2023-07-01', 'en', new Date(2024, 5, 1))).toBe('Sat, July 1, 2023')
  })

  it('shows the time as the clock read where the photo was taken', () => {
    const tokyo = formatTaken({ takenAt: Date.UTC(2024, 6, 1, 14, 30), takenOffset: 540 }, 'en-GB')
    expect(tokyo).toEqual({ date: 'Monday, 1 July 2024', time: '23:30', zone: 'UTC+09:00' })
    expect(formatOffset(-330)).toBe('UTC−05:30')
    expect(formatOffset(0)).toBe('UTC')
  })

  it('writes durations the way players do', () => {
    expect(formatDuration(7_400)).toBe('0:07')
    expect(formatDuration(754_000)).toBe('12:34')
    expect(formatDuration(3_723_000)).toBe('1:02:03')
  })
})
