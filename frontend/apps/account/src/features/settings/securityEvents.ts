import type { SecurityEvent } from './api'
import { describeUserAgent } from './userAgent'

const KNOWN = new Set(['passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset'])
/** Events about a name: their text names it (`oldName`, and `newName` for a rename). */
const NAMED = new Set(['rename', 'nameDropped', 'nameClosed', 'nameFreed'])

/**
 * The locale key for what happened, and its values; a kind added later (or
 * a name event without its names) reads generically.
 */
export function securityEventLabel(event: Pick<SecurityEvent, 'kind' | 'oldName' | 'newName'>): {
  key: string
  values?: Record<string, string>
} {
  if (NAMED.has(event.kind) && event.oldName && (event.kind !== 'rename' || event.newName)) {
    return {
      key: `settings.security.events.kind.${event.kind}`,
      values: { oldName: event.oldName, ...(event.newName ? { newName: event.newName } : {}) },
    }
  }
  return { key: `settings.security.events.kind.${KNOWN.has(event.kind) ? event.kind : 'other'}` }
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
