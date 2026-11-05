import { beforeEach, describe, expect, it } from 'vitest'
import { effectiveUnlockMode } from './autoLock'
import {
  allLocked,
  forgetLock,
  isLocked,
  knownAccount,
  lastDeviceActivity,
  markAllLocked,
  markLocked,
  markUnlocked,
  recordActivity,
  startAccount,
} from './deviceLock'

const ALICE = 'alice-user-id'
const BOB = 'bob-user-id'

beforeEach(() => {
  forgetLock()
  localStorage.removeItem('kutup-pass-activity')
})

describe('the device lock', () => {
  it('is kept in storage, so a new tab or one opened from Drive sees it', () => {
    startAccount(ALICE)
    expect(isLocked(ALICE, 'v1')).toBe(false)
    markLocked(ALICE, 'v1')
    // What another tab reads: the same storage.
    expect(JSON.parse(localStorage.getItem('kutup-pass-lock') ?? '{}').ids).toEqual(['v1'])
    expect(isLocked(ALICE, 'v1')).toBe(true)
    expect(isLocked(ALICE, 'v2')).toBe(false)
    markUnlocked(ALICE, 'v1')
    expect(isLocked(ALICE, 'v1')).toBe(false)
  })

  it('locks every vault at once, each opening again on its own', () => {
    startAccount(ALICE)
    markAllLocked(ALICE)
    expect(allLocked(ALICE)).toBe(true)
    expect(isLocked(ALICE, 'v1')).toBe(true)
    expect(isLocked(ALICE, 'v2')).toBe(true)
    markUnlocked(ALICE, 'v1')
    expect(isLocked(ALICE, 'v1')).toBe(false)
    expect(isLocked(ALICE, 'v2')).toBe(true)
    expect(allLocked(ALICE)).toBe(false)
    // Locked again by hand after being unlocked.
    markLocked(ALICE, 'v1')
    expect(isLocked(ALICE, 'v1')).toBe(true)
  })

  it('belongs to one account, and goes with the sign-out', () => {
    startAccount(ALICE)
    markAllLocked(ALICE)
    expect(knownAccount(ALICE)).toBe(true)
    expect(knownAccount(BOB)).toBe(false)
    expect(isLocked(BOB, 'v1')).toBe(false)
    forgetLock()
    expect(knownAccount(ALICE)).toBe(false)
    expect(isLocked(ALICE, 'v1')).toBe(false)
  })

  it('counts use in any tab, written at most every few seconds', () => {
    expect(lastDeviceActivity()).toBeNull()
    recordActivity(1_000_000)
    expect(lastDeviceActivity()).toBe(1_000_000)
    recordActivity(1_001_000)
    expect(lastDeviceActivity()).toBe(1_000_000)
    recordActivity(1_010_000)
    expect(lastDeviceActivity()).toBe(1_010_000)
  })
})

describe('the unlock mode', () => {
  it('is the one chosen, else the PIN when there is one, else a click', () => {
    expect(effectiveUnlockMode('password', false)).toBe('password')
    expect(effectiveUnlockMode('click', true)).toBe('click')
    expect(effectiveUnlockMode(null, true)).toBe('pin')
    // No PIN and nothing chosen: never a password nobody chose.
    expect(effectiveUnlockMode(null, false)).toBe('click')
    expect(effectiveUnlockMode(null, undefined)).toBeNull()
  })
})
