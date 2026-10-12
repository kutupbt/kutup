// When open vaults lock by themselves (docs/plans/pass.md, K2c): after a
// while without use, as Proton Pass does (the delay is a setting kept on this
// device, 15 minutes unless changed), and as soon as the account's session
// ends here: signed out in this app or another tab of it, or the session
// refused by the server (revoked elsewhere). Signing out also forgets the
// vaults this device kept for offline use.

import { useSyncExternalStore } from 'react'
import { startLogoutListener } from '@kutup/session/sessionSync'
import { getSession, subscribe } from '@kutup/session/store'
import { lockAll, openVaultIds } from './openVaults'
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
 * What opens a vault locked in this tab with its key kept in the account:
 * the account password again (as Proton Pass's password lock), or a click.
 */
export type UnlockMode = 'password' | 'click'
export const DEFAULT_UNLOCK_MODE: UnlockMode = 'password'
const MODE_KEY = 'kutup-pass-unlock-mode'
let currentMode: UnlockMode = DEFAULT_UNLOCK_MODE

export function unlockMode(): UnlockMode {
  try {
    const stored = localStorage.getItem(MODE_KEY)
    if (stored === 'password' || stored === 'click') return stored
  } catch {
    // Storage blocked: the default.
  }
  return DEFAULT_UNLOCK_MODE
}

export function setUnlockMode(mode: UnlockMode): void {
  try {
    localStorage.setItem(MODE_KEY, mode)
  } catch {
    // Kept for this visit only.
  }
  currentMode = mode
  for (const listener of listeners) listener()
}

export function useUnlockMode(): UnlockMode {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => currentMode,
  )
}

/** Whether vaults idle since `lastActivity` lock at `now`. */
export function idleExpired(lastActivity: number, now: number, minutes: number): boolean {
  return minutes > 0 && now - lastActivity >= minutes * 60_000
}

/** Locks every vault and forgets what this device kept for the account. */
export async function lockAndForget(userId: string | null): Promise<void> {
  await lockAll()
  if (userId) await outbox.clear(userId)
}

/**
 * Starts the locks for this tab; returns what stops them. Call once, from
 * the shell.
 */
export function startAutoLock(): () => void {
  current = autoLockMinutes()
  currentMode = unlockMode()
  let lastActivity = Date.now()
  let userId = getSession()?.userId ?? null
  const touch = () => {
    lastActivity = Date.now()
  }
  for (const event of ACTIVITY) window.addEventListener(event, touch, { passive: true, capture: true })
  const timer = window.setInterval(() => {
    if (openVaultIds().length > 0 && idleExpired(lastActivity, Date.now(), current)) void lockAll()
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
    stopSession()
    stopLogout()
  }
}
