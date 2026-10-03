import { useSyncExternalStore } from 'react'

/**
 * The conversation on screen, if any, and whether the page is visible: what
 * decides that messages are read (the read mark, read receipts).
 */

// Usually one conversation is on screen. During a call the call's own
// conversation can open in a panel over the page; the one opened last is the
// one being looked at, and closing it gives the page's back.
const opened: { key: string }[] = []
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

/** Mark a conversation as on screen; the returned function takes it off. */
export function openConversation(key: string): () => void {
  const entry = { key }
  opened.push(entry)
  emit()
  return () => {
    const index = opened.indexOf(entry)
    if (index < 0) return
    opened.splice(index, 1)
    emit()
  }
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/** The conversation being looked at: open and the page visible. */
export function useViewedConversation(): string | null {
  return useSyncExternalStore(subscribe, () => (visible ? (opened[opened.length - 1]?.key ?? null) : null))
}
