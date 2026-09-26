import { LOCATION_LABEL_MAX } from '@kutup/chat-core/types'
import type { Place } from '@kutup/map/list'
import { appUrl } from '@kutup/session/apps'

/**
 * Send a place into a chat: Chat opens and asks which chats. The place rides
 * in the link's fragment, which the browser never sends to a server.
 */
export function sendToChat(place: Pick<Place, 'name' | 'lat' | 'lon'>): void {
  const label = [...place.name].slice(0, LOCATION_LABEL_MAX).join('')
  const fragment = new URLSearchParams({ lat: String(place.lat), lon: String(place.lon), label })
  window.open(appUrl('chat', `/share-place#${fragment.toString()}`), '_blank', 'noopener')
}
