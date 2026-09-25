import { useSyncExternalStore } from 'react'

/**
 * Which list the left pane shows: the chats, or the archived ones (Signal's
 * "Archived chats"). Kept outside the page so opening a conversation from
 * the archive leaves the archive showing.
 */

export type ListPane = 'inbox' | 'archived'

let pane: ListPane = 'inbox'
const listeners = new Set<() => void>()

export function setListPane(next: ListPane): void {
  if (pane === next) return
  pane = next
  for (const listener of listeners) listener()
}

export function useListPane(): ListPane {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => pane,
  )
}
