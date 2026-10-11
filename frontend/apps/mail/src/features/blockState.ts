import { useSyncExternalStore } from 'react'

// The senders the Block dialog is about to block; one dialog at a time,
// mounted once by the shell (BlockSenderHost).

let pending: string[] | null = null
const listeners = new Set<() => void>()

export function openBlockSender(addresses: string[] | null) {
  pending = addresses && addresses.length ? addresses : null
  for (const listener of listeners) listener()
}

export function useBlockSender() {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => pending,
  )
}
