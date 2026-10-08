import type { SealedStorage } from '@kutup/chat-core/sealedStorage'

// The open account's sealed storage (drafts, read positions), or null while
// Chat is not open. Set by the chat store; the state modules read through it.

let current: SealedStorage | null = null
const listeners = new Set<() => void>()

export function setSealedStorage(next: SealedStorage | null): void {
  if (current === next) return
  current = next
  for (const listener of listeners) listener()
}

export function activeSealedStorage(): SealedStorage | null {
  return current
}

/**
 * Notified when the account's storage opens or closes, and when another tab
 * changes the value kept as `name`.
 */
export function subscribeSealed(name: string, listener: () => void): () => void {
  listeners.add(listener)
  const onStorage = (event: StorageEvent) => {
    if (current && event.key === current.key(name)) listener()
  }
  window.addEventListener('storage', onStorage)
  return () => {
    listeners.delete(listener)
    window.removeEventListener('storage', onStorage)
  }
}
