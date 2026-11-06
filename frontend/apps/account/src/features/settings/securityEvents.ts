import type { SecurityEvent } from './api'

const KNOWN = new Set([
  'passwordChange',
  'recovery',
  'rotate',
  'adminReset',
  'accountReset',
  'twoFactorOn',
  'twoFactorOff',
  'recoveryCodeUsed',
  'recoveryCodesRenewed',
  'authenticatorOn',
  'authenticatorOff',
  'signIn',
  'signInFailedPassword',
  'signInFailed2fa',
  'signOut',
  'sessionRevoked',
  'allSessionsRevoked',
  'adminAccess',
])
/**
 * Events about a name, or a named security key: their text names it
 * (`oldName`, and `newName` for a rename).
 */
const NAMED = new Set([
  'rename',
  'nameDropped',
  'nameClosed',
  'nameFreed',
  'securityKeyAdded',
  'securityKeyRemoved',
  'securityKeyCompromised',
])

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
  event: Pick<SecurityEvent, 'client' | 'browser' | 'browserMajor' | 'os'>,
): { key: string; values?: Record<string, string> } | null {
  if (!event.client) return null
  if (event.client === 'cli') return { key: 'settings.sessions.cli' }
  const { browser, os } = clientName(event)
  if (browser && os) return { key: 'settings.sessions.browserOn', values: { browser, os } }
  const one = browser ?? os
  return one ? { key: 'settings.security.events.device', values: { device: one } } : { key: 'settings.sessions.unknownBrowser' }
}

/** A session's browser as it is named: "Firefox 128" and "Linux", or null for each part unknown. */
export function clientName(client: { browser?: string; browserMajor?: number; os?: string }): {
  browser: string | null
  os: string | null
} {
  const browser = client.browser
    ? client.browserMajor !== undefined && client.browser !== 'Kutup CLI'
      ? `${client.browser} ${client.browserMajor}`
      : client.browser
    : null
  return { browser, os: client.os ?? null }
}
