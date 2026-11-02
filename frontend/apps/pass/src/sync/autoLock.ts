// When open vaults lock by themselves (docs/plans/pass.md, K2c): after a
// while without use, as Proton Pass does (the delay is a setting kept on this
// device, 15 minutes unless changed), and as soon as the account's session
// ends here: signed out in this app or another tab of it, or the session
// refused by the server (revoked elsewhere). Signing out also forgets the
// vaults this device kept for offline use. The lock and the idle time are
// the device's, not a tab's (`deviceLock.ts`): every way into a vault (this
// tab, a new one, Drive) meets the same lock and the same unlock.

import { useSyncExternalStore } from 'react'
import { startLogoutListener } from '@kutup/session/sessionSync'
import { getSession, subscribe } from '@kutup/session/store'
import { allLocked, forgetLock, joinDeviceLock, knownAccount, lastDeviceActivity, recordActivity, startAccount } from './deviceLock'
import { closeAllHere, closeLockedHere, lockAll, openVaultIds } from './openVaults'
import { usePinStatus } from './pin'
import { outbox } from './outbox'

/** The delays offered, in minutes; 0 locks only on sign-out. */
export const AUTO_LOCK_CHOICES = [1, 5, 15, 30, 60, 240, 0] as const
export type AutoLockMinutes = (typeof AUTO_LOCK_CHOICES)[number]
export const DEFAULT_AUTO_LOCK: AutoLockMinutes = 15

const STORAGE_KEY = 'kutup-pass-auto-lock-minutes'
const CHECK_MS = 15_000
const ACTIVITY = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const

const listeners = new Set<() => void>()

export function autoLockMinutes(): AutoLockMinutes {
  try {
    const stored = Number(localStorage.getItem(STORAGE_KEY))
    if ((AUTO_LOCK_CHOICES as readonly number[]).includes(stored) && localStorage.getItem(STORAGE_KEY) !== null) return stored as AutoLockMinutes
  } catch {
    // Storage blocked: the default.
  }
  return DEFAULT_AUTO_LOCK
}

export function setAutoLockMinutes(minutes: AutoLockMinutes): void {
  try {
    localStorage.setItem(STORAGE_KEY, String(minutes))
  } catch {
    // Kept for this visit only.
  }
  current = minutes
  for (const listener of listeners) listener()
}

let current: AutoLockMinutes = DEFAULT_AUTO_LOCK

export function useAutoLockMinutes(): AutoLockMinutes {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => current,
  )
}

/**
 * What opens a locked vault whose key the account keeps: the account
 * password again (as Proton Pass's password lock), the account's PIN (its
 * PIN lock, `sync/pin.ts`), or a click. The same at every way in.
 */
export type UnlockMode = 'password' | 'pin' | 'click'
const MODE_KEY = 'kutup-pass-unlock-mode'
let chosenMode: UnlockMode | null = null

/** The mode chosen on this device, if one was. */
export function chosenUnlockMode(): UnlockMode | null {
  try {
    const stored = localStorage.getItem(MODE_KEY)
    if (stored === 'password' || stored === 'pin' || stored === 'click') return stored
  } catch {
    // Storage blocked: none chosen.
  }
  return null
}

/** Chooses the mode on this device; null goes back to the default. */
export function setUnlockMode(mode: UnlockMode | null): void {
  try {
    if (mode) localStorage.setItem(MODE_KEY, mode)
    else localStorage.removeItem(MODE_KEY)
  } catch {
    // Kept for this visit only.
  }
  chosenMode = mode
  for (const listener of listeners) listener()
}

/**
 * The mode in force: the one chosen, else the PIN when the account has one,
 * else a click. A password nobody chose is never asked for (the vault's key
 * is kept for quick opening). `pinSet` undefined: not known yet.
 */
export function effectiveUnlockMode(chosen: UnlockMode | null, pinSet: boolean | undefined): UnlockMode | null {
  if (chosen) return chosen
  if (pinSet === undefined) return null
  return pinSet ? 'pin' : 'click'
}

/** The mode chosen on this device (null: the default), kept current. */
export function useChosenUnlockMode(): UnlockMode | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => chosenMode,
  )
}

/**
 * The mode in force here, or null while the account's PIN status is still
 * being read. When it can't be read, the password: whether a PIN guards the
 * vaults isn't known, and a blocked request must not skip one.
 */
export function useUnlockMode(): UnlockMode | null {
  const chosen = useChosenUnlockMode()
  const pin = usePinStatus()
  if (!chosen && pin.isError) return 'password'
  return effectiveUnlockMode(chosen, pin.data)
}

/** Whether vaults idle since `lastActivity` lock at `now`. */
export function idleExpired(lastActivity: number, now: number, minutes: number): boolean {
  return minutes > 0 && now - lastActivity >= minutes * 60_000
}

/** Locks every vault and forgets what this device kept for the account. */
export async function lockAndForget(userId: string | null): Promise<void> {
  await closeAllHere()
  forgetLock()
  if (userId) await outbox.clear(userId)
}

/**
 * Starts the locks for this tab; returns what stops them. Call once, from
 * the shell.
 */
export function startAutoLock(): () => void {
  current = autoLockMinutes()
  chosenMode = chosenUnlockMode()
  let userId = getSession()?.userId ?? null
  // Opened after the device idled past the delay: locked from the start.
  // An account this device holds no lock for yet has just signed in.
  if (userId) {
    const last = lastDeviceActivity()
    if (!knownAccount(userId)) startAccount(userId)
    else if (last !== null && idleExpired(last, Date.now(), current)) void lockAll()
  }
  let lastActivity = Date.now()
  recordActivity(lastActivity)
  const touch = () => {
    lastActivity = Date.now()
    recordActivity(lastActivity)
  }
  for (const event of ACTIVITY) window.addEventListener(event, touch, { passive: true, capture: true })
  const stopDevice = joinDeviceLock({
    lockAll: () => void closeAllHere(),
    lock: (fileId) => void closeLockedHere(fileId),
  })
  const timer = window.setInterval(() => {
    // Use in any tab of this device counts.
    const last = Math.max(lastActivity, lastDeviceActivity() ?? 0)
    if (!idleExpired(last, Date.now(), current)) return
    const account = getSession()?.userId
    if (openVaultIds().length > 0 || (account && !allLocked(account))) void lockAll()
  }, CHECK_MS)
  // Signed out here (the session cleared) or in another tab of Pass.
  const stopSession = subscribe(() => {
    const now = getSession()
    if (!now && userId) void lockAndForget(userId)
    userId = now?.userId ?? userId
  })
  const stopLogout = startLogoutListener(() => void lockAndForget(userId))
  return () => {
    for (const event of ACTIVITY) window.removeEventListener(event, touch, { capture: true })
    window.clearInterval(timer)
    stopDevice()
    stopSession()
    stopLogout()
  }
}
