import { useSyncExternalStore } from 'react'

/** Whether Calendar's shortcuts list is open (`?`, or Settings). */
let open = false
const listeners = new Set<() => void>()

export function openShortcuts(next = true): void {
  open = next
  for (const listener of listeners) listener()
}

export function useShortcutsOpen(): boolean {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => open,
  )
}
