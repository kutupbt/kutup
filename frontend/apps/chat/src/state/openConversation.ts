import { useSyncExternalStore } from 'react'

/**
 * The conversation on screen, if any, and whether the page is visible: what
 * decides that messages are read (the read mark, read receipts).
 */

let openKey: string | null = null
let visible = typeof document === 'undefined' ? true : document.visibilityState === 'visible'
const listeners = new Set<() => void>()

function emit() {
  for (const listener of listeners) listener()
}

if (typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', () => {
    visible = document.visibilityState === 'visible'
    emit()
  })
}

export function setOpenConversation(key: string | null): void {
  if (openKey === key) return
  openKey = key
  emit()
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/** The conversation being looked at: open and the page visible. */
export function useViewedConversation(): string | null {
  return useSyncExternalStore(subscribe, () => (visible ? openKey : null))
}
