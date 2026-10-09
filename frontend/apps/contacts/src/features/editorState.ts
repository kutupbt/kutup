import { useSyncExternalStore } from 'react'
import type { Contact } from '@kutup/contacts-core/model'

// Which contact the editor dialog shows, shared by the sidebar's "New
// contact", the person page's "Edit" and the list.

export type EditorTarget = { kind: 'new'; groupId?: string } | { kind: 'edit'; contact: Contact }

let target: EditorTarget | null = null
const listeners = new Set<() => void>()

function set(next: EditorTarget | null) {
  target = next
  for (const listener of listeners) listener()
}

export function useEditor() {
  const current = useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => target,
  )
  return { target: current, open: (next: EditorTarget) => set(next), close: () => set(null) }
}
