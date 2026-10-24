import { describe, expect, it } from 'vitest'
import { hasRepeats, minutesTrigger, newRow, reminderOf, rowOf, triggerMinutes } from './triggers'

describe('the picker’s triggers, as Proton writes them', () => {
  it('reads and writes durations', () => {
    expect(triggerMinutes('-PT15M')).toBe(-15)
    expect(triggerMinutes('-P1DT2H30M')).toBe(-(1440 + 150))
    expect(triggerMinutes('PT9H')).toBe(540)
    expect(triggerMinutes('PT0S')).toBe(0)
    expect(triggerMinutes('-P2W')).toBe(-20160)
    expect(triggerMinutes('nonsense')).toBeNull()
    expect(minutesTrigger(-15)).toBe('-PT15M')
    expect(minutesTrigger(-60)).toBe('-PT1H')
    expect(minutesTrigger(-1440)).toBe('-P1D')
    expect(minutesTrigger(-900)).toBe('-PT15H')
    expect(minutesTrigger(-20160)).toBe('-P2W')
    expect(minutesTrigger(570)).toBe('PT9H30M')
    expect(minutesTrigger(0)).toBe('PT0S')
  })

  it('shows a timed event’s reminder in its largest whole unit', () => {
    expect(rowOf({ type: 'device', trigger: '-PT15M' }, false)).toEqual({ type: 'device', value: 15, unit: 'minute', at: 0 })
    expect(rowOf({ type: 'email', trigger: '-PT2H' }, false)).toEqual({ type: 'email', value: 2, unit: 'hour', at: 0 })
    expect(rowOf({ type: 'device', trigger: '-P1D' }, false)).toEqual({ type: 'device', value: 1, unit: 'day', at: 0 })
    expect(rowOf({ type: 'device', trigger: 'PT0S' }, false)).toEqual({ type: 'device', value: 0, unit: 'minute', at: 0 })
  })

  it('shows an all-day event’s as days or weeks before, at a time of day', () => {
    // Proton's default: the day before at 09:00.
    expect(rowOf({ type: 'device', trigger: '-PT15H' }, true)).toEqual({ type: 'device', value: 1, unit: 'day', at: 540 })
    expect(rowOf({ type: 'device', trigger: 'PT9H' }, true)).toEqual({ type: 'device', value: 0, unit: 'day', at: 540 })
    expect(rowOf({ type: 'email', trigger: '-P7D' }, true)).toEqual({ type: 'email', value: 1, unit: 'week', at: 0 })
  })

  it('writes back what it shows', () => {
    for (const [trigger, allDay] of [
      ['-PT15M', false],
      ['-PT3H', false],
      ['-P2D', false],
      ['PT0S', false],
      ['-PT15H', true],
      ['PT9H', true],
      ['-P1DT14H', true],
    ] as const) {
      const row = rowOf({ type: 'device', trigger }, allDay)!
      expect(triggerMinutes(reminderOf(row, allDay).trigger)).toBe(triggerMinutes(trigger))
    }
    expect(reminderOf(newRow(true), true)).toEqual({ type: 'device', trigger: '-PT15H' })
    expect(reminderOf(newRow(false), false)).toEqual({ type: 'device', trigger: '-PT15M' })
  })

  it('finds the same reminder twice', () => {
    expect(hasRepeats([{ type: 'device', trigger: '-PT60M' }, { type: 'device', trigger: '-PT1H' }])).toBe(true)
    expect(hasRepeats([{ type: 'device', trigger: '-PT1H' }, { type: 'email', trigger: '-PT1H' }])).toBe(false)
  })
})
