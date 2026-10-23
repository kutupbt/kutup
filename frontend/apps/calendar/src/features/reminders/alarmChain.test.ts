import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Alarm } from '@kutup/calendar-core/api'
import { alarmTag, runAlarms } from './alarmChain'

const T0 = Date.parse('2026-10-29T09:00:00Z')
const alarm = (eventId: string, fireOffsetMs: number, occurrence = '2026-10-29T09:15:00Z'): Alarm => ({
  calendarId: 'c',
  eventId,
  action: 'device',
  occurrenceStart: occurrence,
  fireAt: new Date(T0 + fireOffsetMs).toISOString(),
})

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(T0)
})
afterEach(() => vi.useRealTimers())

describe('the open app’s reminders (Proton’s AlarmWatcher)', () => {
  it('fires each alarm in turn, at its time, once', async () => {
    const fired = new Set<string>()
    const shown: string[] = []
    const stop = runAlarms([alarm('a', 1_000), alarm('b', 5_000)], fired, (a) => {
      shown.push(a.eventId)
      return Promise.resolve()
    })
    await vi.advanceTimersByTimeAsync(999)
    expect(shown).toEqual([])
    await vi.advanceTimersByTimeAsync(1)
    expect(shown).toEqual(['a'])
    await vi.advanceTimersByTimeAsync(4_000)
    expect(shown).toEqual(['a', 'b'])
    stop()
    // Refetched: the same alarms never fire again.
    const again = runAlarms([alarm('a', 1_000), alarm('b', 5_000)], fired, (a) => {
      shown.push(a.eventId)
      return Promise.resolve()
    })
    await vi.advanceTimersByTimeAsync(10_000)
    expect(shown).toEqual(['a', 'b'])
    again()
  })

  it('skips one more than a minute late, and fires one less late at once', async () => {
    const shown: string[] = []
    const stop = runAlarms([alarm('late', -61_000), alarm('just', -30_000)], new Set(), (a) => {
      shown.push(a.eventId)
      return Promise.resolve()
    })
    await vi.advanceTimersByTimeAsync(10)
    expect(shown).toEqual(['just'])
    stop()
  })

  it('stops when told, and goes on after one that fails', async () => {
    const shown: string[] = []
    const stop = runAlarms([alarm('a', 1_000), alarm('b', 2_000)], new Set(), (a) => {
      shown.push(a.eventId)
      return a.eventId === 'a' ? Promise.reject(new Error('no event')) : Promise.resolve()
    })
    await vi.advanceTimersByTimeAsync(2_000)
    expect(shown).toEqual(['a', 'b'])
    stop()
    const none: string[] = []
    const stopped = runAlarms([alarm('c', 1_000)], new Set(), (a) => {
      none.push(a.eventId)
      return Promise.resolve()
    })
    stopped()
    await vi.advanceTimersByTimeAsync(5_000)
    expect(none).toEqual([])
  })

  it('names an alarm as the push does: its event and occurrence', () => {
    expect(alarmTag(alarm('e1', 0))).toBe(`kutup-calendar:e1:${Date.parse('2026-10-29T09:15:00Z')}`)
  })
})
