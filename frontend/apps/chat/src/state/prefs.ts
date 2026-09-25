import { useSyncExternalStore } from 'react'

/**
 * Chat preferences kept on this device, each one switch in localStorage.
 *
 * - Read receipts are off unless turned on (the old page's storage key):
 *   delivery receipts in direct chats are always sent; "read" only when on.
 * - Link previews are on, as in Signal: typing a link asks this account's
 *   server to fetch the page, and the preview travels encrypted.
 */

function booleanPref(key: string, fallback: boolean) {
  const listeners = new Set<() => void>()
  const read = (): boolean => {
    try {
      const value = window.localStorage.getItem(key)
      return value === null ? fallback : value === '1'
    } catch {
      return fallback
    }
  }
  let current = read()
  return {
    set: (enabled: boolean): void => {
      current = enabled
      try {
        window.localStorage.setItem(key, enabled ? '1' : '0')
      } catch {
        // Kept for this tab only.
      }
      for (const listener of listeners) listener()
    },
    use: (): boolean =>
      useSyncExternalStore(
        (listener) => {
          listeners.add(listener)
          return () => listeners.delete(listener)
        },
        () => current,
      ),
  }
}

const readReceipts = booleanPref('kutup:chat:read-receipts', false)
const linkPreviews = booleanPref('kutup:chat:link-previews', true)

export const setReadReceipts = readReceipts.set
export const useReadReceipts = readReceipts.use
export const setLinkPreviews = linkPreviews.set
export const useLinkPreviews = linkPreviews.use
