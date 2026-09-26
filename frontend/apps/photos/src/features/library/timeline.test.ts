import { describe, expect, it } from 'vitest'
import { columnsFor, dayKey, daysOf, newestFirst, takenParts, timelineRows } from './timeline'

describe('timeline', () => {
  it('puts a photo on the day it was taken where it was taken', () => {
    // 23:30 in Tokyo (UTC+9) is 14:30 UTC: still the 1st in Tokyo.
    const tokyo = { takenAt: Date.UTC(2024, 6, 1, 14, 30), takenOffset: 540 }
    expect(dayKey(tokyo)).toBe('2024-07-01')
    expect(takenParts(tokyo)).toMatchObject({ hour: 23, minute: 30 })
    // 00:30 in New York (UTC−4) is 04:30 UTC on the 2nd: the 2nd there.
    expect(dayKey({ takenAt: Date.UTC(2024, 6, 2, 4, 30), takenOffset: -240 })).toBe('2024-07-02')
  })

  it("uses this device's time zone when the photo does not say", () => {
    const local = new Date(2023, 0, 5, 22, 0).getTime()
    expect(dayKey({ takenAt: local })).toBe('2023-01-05')
  })

  it('sorts newest first, stably', () => {
    const items = [
      { id: 'b', takenAt: 10 },
      { id: 'a', takenAt: 10 },
      { id: 'c', takenAt: 30 },
    ]
    expect(newestFirst(items).map((i) => i.id)).toEqual(['c', 'a', 'b'])
  })

  it('groups by day, with a heading at each new month, cut into rows', () => {
    const at = (m: number, d: number, h = 12) => Date.UTC(2024, m - 1, d, h)
    const items = newestFirst([
      { id: '1', takenAt: at(7, 2), takenOffset: 0 },
      { id: '2', takenAt: at(7, 2, 9), takenOffset: 0 },
      { id: '3', takenAt: at(7, 2, 8), takenOffset: 0 },
      { id: '4', takenAt: at(7, 1), takenOffset: 0 },
      { id: '5', takenAt: at(6, 30), takenOffset: 0 },
    ])
    const days = daysOf(items)
    expect(days.map((d) => [d.day, d.items.length])).toEqual([
      ['2024-07-02', 3],
      ['2024-07-01', 1],
      ['2024-06-30', 1],
    ])
    const rows = timelineRows(days, 2)
    expect(rows.map((r) => (r.kind === 'photos' ? `photos:${r.items.map((i) => i.id).join('')}` : `${r.kind}:${r.kind === 'month' ? r.month : r.day}`))).toEqual([
      'month:2024-07',
      'day:2024-07-02',
      'photos:12',
      'photos:3',
      'day:2024-07-01',
      'photos:4',
      'month:2024-06',
      'day:2024-06-30',
      'photos:5',
    ])
  })

  it('fits as many tiles as the width allows, never fewer than three', () => {
    expect(columnsFor(1000, 160, 4)).toBe(6)
    expect(columnsFor(320, 160, 4)).toBe(3)
  })
})
