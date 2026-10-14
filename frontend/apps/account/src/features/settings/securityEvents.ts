import type { SecurityEvent } from './api'

const KNOWN = new Set(['passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset'])

/** The locale key for what happened; a kind added later reads generically. */
export function securityEventLabel(event: Pick<SecurityEvent, 'kind'>): string {
  return `settings.security.events.kind.${KNOWN.has(event.kind) ? event.kind : 'other'}`
}
