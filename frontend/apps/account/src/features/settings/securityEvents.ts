import type { SecurityEvent } from './api'
import { describeUserAgent } from './userAgent'

const KNOWN = new Set(['passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset'])

/** The locale key for what happened; a kind added later reads generically. */
export function securityEventLabel(event: Pick<SecurityEvent, 'kind'>): string {
  return `settings.security.events.kind.${KNOWN.has(event.kind) ? event.kind : 'other'}`
}

/**
 * Where it was done, as the session list names devices: the locale key and
 * its values, or null when no session did it (a recovery, an administrator).
 */
export function securityEventDevice(
  event: Pick<SecurityEvent, 'client' | 'userAgent'>,
): { key: string; values?: Record<string, string> } | null {
  if (!event.client) return null
  if (event.client === 'cli') return { key: 'settings.sessions.cli' }
  const { browser, os } = describeUserAgent(event.userAgent)
  if (browser && os) return { key: 'settings.sessions.browserOn', values: { browser, os } }
  const one = browser ?? os
  return one ? { key: 'settings.security.events.device', values: { device: one } } : { key: 'settings.sessions.unknownBrowser' }
}
