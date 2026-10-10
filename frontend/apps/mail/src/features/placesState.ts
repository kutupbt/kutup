import { useSyncExternalStore } from 'react'
import type { MailFolder, MailLabel } from '@kutup/mail-core/places'
import type { PlaceTarget } from './PlaceDialog'

// The folder or label dialog open now, from the sidebar, a menu or a picker;
// one at a time, mounted once by the shell (PlacesHost).

export type PlacesDialog =
  | { kind: 'edit'; target: PlaceTarget; onCreated?: (id: string, name: string) => void }
  | { kind: 'delete'; folder?: MailFolder; label?: MailLabel }

let current: PlacesDialog | null = null
const listeners = new Set<() => void>()

export function openPlacesDialog(next: PlacesDialog | null) {
  current = next
  for (const listener of listeners) listener()
}

export function usePlacesDialog() {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => current,
  )
}
