import { useSyncExternalStore } from 'react'
import type { SealedStorage } from '@kutup/chat-core/sealedStorage'
import { activeSealedStorage, subscribeSealed } from './sealedState'

/**
 * How far each conversation has been read on this device: the timestamp of
 * the newest message shown while it was open and the page visible. Unread
 * counts and the "unread messages" marker come from it. It is per device
 * (like the drafts), sealed for the account; read receipts to the other
 * side are separate and optional.
 */

type ReadMarks = Record<string, number>

const NAME = 'read-marks'
const listeners = new Set<() => void>()
/** `fresh`: this device has no marks yet (first open), so everything starts read. */
let cache: { storage: SealedStorage | null; marks: ReadMarks; fresh: boolean } | null = null

function load(): { marks: ReadMarks; fresh: boolean } {
  const storage = activeSealedStorage()
  if (cache?.storage !== storage) {
    const stored = storage?.read<unknown>(NAME)
    cache = {
      storage,
      marks: stored && typeof stored === 'object' ? (stored as ReadMarks) : {},
      fresh: storage !== null && stored === undefined,
    }
  }
  return cache
}

function store(marks: ReadMarks): void {
  const storage = activeSealedStorage()
  cache = { storage, marks, fresh: false }
  storage?.write(NAME, marks)
  for (const listener of listeners) listener()
}

/**
 * On a device's first open, what history there already is (restored from
 * the backup, synced from other devices) counts as read: only what arrives
 * from now on is new.
 */
export function startFreshMarks(newestByKey: ReadonlyMap<string, number>): void {
  const { marks, fresh } = load()
  if (!fresh) return
  store({ ...Object.fromEntries(newestByKey), ...marks })
}

/** Mark `key` read up to `timestampMs` (never backwards). */
export function markRead(key: string, timestampMs: number): void {
  if (!activeSealedStorage()) return
  const { marks } = load()
  if ((marks[key] ?? 0) >= timestampMs) return
  store({ ...marks, [key]: timestampMs })
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  const unsubscribe = subscribeSealed(NAME, () => {
    cache = null
    listener()
  })
  return () => {
    listeners.delete(listener)
    unsubscribe()
  }
}

export function useReadMarks(): Readonly<ReadMarks> {
  return useSyncExternalStore(subscribe, () => load().marks)
}
