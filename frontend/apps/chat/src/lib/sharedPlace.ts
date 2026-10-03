import { useSyncExternalStore } from 'react'
import { LOCATION_LABEL_MAX, type ChatLocationV1 } from '@kutup/chat-core/types'

// A place another Kutup app (Maps) asked to send into a chat
// (docs/plans/maps.md, step 4): `/share-place#lat=…&lon=…&label=…`. It rides
// in the fragment, which never leaves the browser; one dialog at the top of
// the app asks which chats it goes to.

let current: ChatLocationV1 | null = null
const listeners = new Set<() => void>()

function set(next: ChatLocationV1 | null): void {
  current = next
  for (const listener of listeners) listener()
}

/** The place in a `/share-place` fragment, or null when it is not a valid one. */
export function parseSharedPlace(hash: string): ChatLocationV1 | null {
  const params = new URLSearchParams(hash.replace(/^#/, ''))
  const lat = Number(params.get('lat'))
  const lon = Number(params.get('lon'))
  if (!params.has('lat') || !params.has('lon') || !Number.isFinite(lat) || !Number.isFinite(lon)) return null
  if (lat < -90 || lat > 90 || lon < -180 || lon > 180) return null
  const label = [...(params.get('label') ?? '').trim()].slice(0, LOCATION_LABEL_MAX).join('')
  return { lat, lon, ...(label ? { label } : {}) }
}

export function openSharedPlace(place: ChatLocationV1): void {
  set(place)
}

export function closeSharedPlace(): void {
  set(null)
}

export function useSharedPlace(): ChatLocationV1 | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => current,
  )
}
