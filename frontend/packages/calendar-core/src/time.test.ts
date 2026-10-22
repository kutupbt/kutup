import { describe, expect, it } from 'vitest'
import { addDays, addMonths, daysBetween, isCivilDate, minutesOf, monthGrid, startOfWeek, step, viewDays, weekday } from './time'

describe('calendar dates', () => {
  it('counts days across months, years and daylight-saving changes', () => {
    expect(addDays('2026-10-31', 1)).toBe('2026-11-01')
    expect(addDays('2026-12-31', 1)).toBe('2027-01-01')
    // Europe changes clocks on 2026-10-25: a civil day is still one day.
    expect(addDays('2026-10-24', 2)).toBe('2026-10-26')
    expect(daysBetween('2026-10-29', '2026-11-02')).toBe(4)
    expect(addMonths('2026-12-15', 1)).toBe('2027-01-01')
    expect(addMonths('2026-01-31', -1)).toBe('2025-12-01')
    expect(isCivilDate('2026-02-30')).toBe(false)
  })

  it('starts weeks on the chosen day', () => {
    // 2026-10-29 is a Thursday.
    expect(weekday('2026-10-29')).toBe(4)
    expect(startOfWeek('2026-10-29', 1)).toBe('2026-10-26')
    expect(startOfWeek('2026-10-29', 0)).toBe('2026-10-25')
    expect(startOfWeek('2026-10-26', 1)).toBe('2026-10-26')
    expect(viewDays('week', '2026-10-29', 1)).toEqual([
      '2026-10-26', '2026-10-27', '2026-10-28', '2026-10-29', '2026-10-30', '2026-10-31', '2026-11-01',
    ])
  })

  it('lays a month out in six weeks around its first day', () => {
    const grid = monthGrid('2026-10-29', 1)
    expect(grid).toHaveLength(6)
    expect(grid[0][0]).toBe('2026-09-28')
    expect(grid[0]).toContain('2026-10-01')
    expect(grid[5][6]).toBe('2026-11-08')
    expect(step('month', '2026-10-29', 1)).toBe('2026-11-01')
    expect(step('week', '2026-10-29', -1)).toBe('2026-10-22')
  })

  it('reads minutes of a local time', () => {
    expect(minutesOf('2026-10-29T09:30:00')).toBe(570)
  })
})
