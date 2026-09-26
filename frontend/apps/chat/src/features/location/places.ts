import type { ChatLocationV1 } from '@kutup/chat-core/types'

/** "41.00820, 28.97840": five decimals, about a metre. */
export function formatCoordinates(place: Pick<ChatLocationV1, 'lat' | 'lon'>): string {
  return `${place.lat.toFixed(5)}, ${place.lon.toFixed(5)}`
}

/**
 * Where "Open in maps" goes: the phone's maps app on Android (`geo:`) and iOS
 * (Apple Maps), OpenStreetMap elsewhere. Only followed when the person taps
 * it; nothing is fetched to show the link.
 */
export function openInMapsUrl(place: ChatLocationV1, userAgent = navigator.userAgent): string {
  const { lat, lon } = place
  const label = place.label ?? ''
  if (/iPhone|iPad|iPod/.test(userAgent)) {
    return `https://maps.apple.com/?ll=${lat},${lon}${label ? `&q=${encodeURIComponent(label)}` : ''}`
  }
  if (/Android/.test(userAgent)) {
    return `geo:${lat},${lon}?q=${lat},${lon}${label ? `(${encodeURIComponent(label)})` : ''}`
  }
  return `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}`
}
