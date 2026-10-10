import { useSyncExternalStore } from 'react'
import type { Mailbox } from '@kutup/mail-core/mime'

// The address being saved to Contacts, from a person card or the banner on
// a message; one dialog at a time, mounted once by the shell.

let saving: Mailbox | null = null
const listeners = new Set<() => void>()

function set(next: Mailbox | null) {
  saving = next
  for (const listener of listeners) listener()
}

export function useSaving() {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => saving,
  )
}

/** Opens Save to contacts for `mailbox` (null closes it). */
export function useSaveContact() {
  return set
}
