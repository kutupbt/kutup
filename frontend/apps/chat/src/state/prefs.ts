import { useSyncExternalStore } from 'react'

/**
 * Chat preferences kept on this device. Read receipts are off unless
 * turned on (as in the old page, same storage key): delivery receipts in
 * direct chats are always sent; "read" only when this is on.
 */

const READ_RECEIPTS_KEY = 'kutup:chat:read-receipts'
const listeners = new Set<() => void>()

function read(): boolean {
  try {
    return window.localStorage.getItem(READ_RECEIPTS_KEY) === '1'
  } catch {
    return false
  }
}

let readReceipts = read()

export function setReadReceipts(enabled: boolean): void {
  readReceipts = enabled
  try {
    window.localStorage.setItem(READ_RECEIPTS_KEY, enabled ? '1' : '0')
  } catch {
    // Kept for this tab only.
  }
  for (const listener of listeners) listener()
}

export function useReadReceipts(): boolean {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => readReceipts,
  )
}
