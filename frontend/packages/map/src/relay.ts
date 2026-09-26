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
