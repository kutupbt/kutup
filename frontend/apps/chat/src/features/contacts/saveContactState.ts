import { useSyncExternalStore } from 'react'

// The person being saved to Contacts, from the details panel, a group's
// member list or the banner in a conversation; one dialog at a time,
// mounted once by the shell (as Mail does).

export type Saving = { address: string; name?: string }

let saving: Saving | null = null
const listeners = new Set<() => void>()

function set(next: Saving | null) {
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

/** Opens Save to contacts for a person (null closes it). */
export function useSaveContact() {
  return set
}
