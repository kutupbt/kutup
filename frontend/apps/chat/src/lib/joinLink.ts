import { useSyncExternalStore } from 'react'

// The group link being looked at, if any: opened from /join, from a link in
// a message, or pasted; one dialog at the top of the app shows it.

let current: string | null = null
const listeners = new Set<() => void>()

function set(next: string | null): void {
  current = next
  for (const listener of listeners) listener()
}

/** Show what `url` leads to; `''` asks for a link to paste. */
export function openJoinLink(url: string): void {
  set(url)
}

export function closeJoinLink(): void {
  set(null)
}

export function useJoinLink(): string | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => current,
  )
}
