import { describe, expect, it } from 'vitest'
import { autoLockMinutes, DEFAULT_AUTO_LOCK, idleExpired, setAutoLockMinutes } from './autoLock'

describe('auto-lock', () => {
  it('locks after the chosen idle time, never with 0', () => {
    const start = 1_000_000
    expect(idleExpired(start, start + 14 * 60_000, 15)).toBe(false)
    expect(idleExpired(start, start + 15 * 60_000, 15)).toBe(true)
    expect(idleExpired(start, start + 60_000, 1)).toBe(true)
    expect(idleExpired(start, start + 10 * 24 * 3_600_000, 0)).toBe(false)
  })

  it('defaults to 15 minutes and keeps a choice on this device', () => {
    localStorage.removeItem('kutup-pass-auto-lock-minutes')
    expect(autoLockMinutes()).toBe(DEFAULT_AUTO_LOCK)
    setAutoLockMinutes(5)
    expect(autoLockMinutes()).toBe(5)
    setAutoLockMinutes(0)
    expect(autoLockMinutes()).toBe(0)
    localStorage.setItem('kutup-pass-auto-lock-minutes', '7')
    expect(autoLockMinutes()).toBe(DEFAULT_AUTO_LOCK)
  })
})
