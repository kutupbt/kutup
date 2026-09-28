import type { StyleSpecification } from 'maplibre-gl'
import { getAccessToken } from '@kutup/session/store'

export interface RelayRequest {
  url: string
  headers?: Record<string, string>
}

/**
 * Requests to this server's map relay carry the session's token; a relayed
 * style names its tiles, glyphs and sprites by path, which is made absolute
 * here. Nothing is added to requests that go straight to a provider.
 */
export function relayRequest(url: string, origin = window.location.origin): RelayRequest {
  const absolute = url.startsWith('/api/') ? origin + url : url
  if (!absolute.startsWith(`${origin}/api/maps/proxy/`)) return { url: absolute }
  const token = getAccessToken()
  return { url: absolute, headers: token ? { Authorization: `Bearer ${token}` } : {} }
}

/**
 * A relayed style names its sprite and glyphs by path on this origin (the
 * relay rewrites the provider's URLs); MapLibre wants them absolute, so they
 * are made so as the style loads (`setStyle`'s `transformStyle`).
 */
export function absoluteStyle(style: StyleSpecification, origin = window.location.origin): StyleSpecification {
  const absolute = (url: string) => (url.startsWith('/') ? origin + url : url)
  const sprite = style.sprite
  return {
    ...style,
    ...(typeof sprite === 'string'
      ? { sprite: absolute(sprite) }
      : Array.isArray(sprite)
        ? { sprite: sprite.map((s) => ({ ...s, url: absolute(s.url) })) }
        : {}),
    ...(style.glyphs ? { glyphs: absolute(style.glyphs) } : {}),
  }
}
