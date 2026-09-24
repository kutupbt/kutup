import { useSyncExternalStore } from 'react'

/**
 * How far each conversation has been read on this device: the timestamp of
 * the newest message shown while it was open and the page visible. Unread
 * counts and the "unread messages" marker come from it. It is per device
 * (like the drafts), kept in localStorage per account; read receipts to
 * the other side are separate and optional.
 */

type ReadMarks = Record<string, number>

const listeners = new Set<() => void>()
let account: string | null = null
let marks: ReadMarks = {}
/** This device has no marks yet (first open): everything starts read. */
let fresh = false

function storageKey(userId: string): string {
  return `kutup:chat:read:${userId}`
}

/** Load this account's marks (once per account). */
export function loadReadMarks(userId: string): void {
  if (account === userId) return
  account = userId
  try {
    const raw = window.localStorage.getItem(storageKey(userId))
    fresh = raw === null
    const parsed: unknown = raw ? JSON.parse(raw) : {}
    marks = parsed && typeof parsed === 'object' ? (parsed as ReadMarks) : {}
  } catch {
    marks = {}
  }
  for (const listener of listeners) listener()
}

/**
 * On a device's first open, what history there already is (restored from
 * the backup, synced from other devices) counts as read: only what arrives
 * from now on is new.
 */
export function startFreshMarks(newestByKey: ReadonlyMap<string, number>): void {
  if (!fresh || !account) return
  fresh = false
  marks = { ...Object.fromEntries(newestByKey), ...marks }
  try {
    window.localStorage.setItem(storageKey(account), JSON.stringify(marks))
  } catch {
    // Kept for this tab.
  }
  for (const listener of listeners) listener()
}

/** Mark `key` read up to `timestampMs` (never backwards). */
export function markRead(key: string, timestampMs: number): void {
  if (!account || (marks[key] ?? 0) >= timestampMs) return
  marks = { ...marks, [key]: timestampMs }
  try {
    window.localStorage.setItem(storageKey(account), JSON.stringify(marks))
  } catch {
    // Storage full or blocked: the marks still hold for this tab.
  }
  for (const listener of listeners) listener()
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  const onStorage = (event: StorageEvent) => {
    if (account && event.key === storageKey(account)) {
      account = null
      const reload = event.key.slice('kutup:chat:read:'.length)
      loadReadMarks(reload)
    }
  }
  window.addEventListener('storage', onStorage)
  return () => {
    listeners.delete(listener)
    window.removeEventListener('storage', onStorage)
  }
}

export function useReadMarks(): Readonly<ReadMarks> {
  return useSyncExternalStore(subscribe, () => marks)
}

/** The read mark of `key` now (0 when never opened). */
export function getReadMark(key: string): number {
  return marks[key] ?? 0
}
