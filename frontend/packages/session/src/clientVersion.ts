// What this web build says it is on every request it makes itself, and the
// latch for the server's answer that it is too old
// (docs/plans/api-surface.md §1.2, §1.5). The axios client uses it, and so
// does every raw fetch, tus upload and WebSocket (`clientFetch`,
// `clientHeaders`, `withClientParam`): one place, so none forgets.

import { clientHeader } from './release'

/** The header naming the client type and its release. */
export const CLIENT_HEADER = 'X-Kutup-Client'
/** What the page dispatches when it must reload (`@kutup/config` reloadGuard.ts `RELOAD_NEEDED_EVENT`). */
const RELOAD_NEEDED_EVENT = 'kutup:reload-needed'

let value: string | null = null
let tooOld = false

/** Set once at boot (configureClient): `<clientType>/<release>`. */
export function setClientType(clientType: string): void {
  value = clientHeader(clientType)
}

/** This page's `X-Kutup-Client` value, or null before configureClient (a Worker passes it in). */
export function clientVersionValue(): string | null {
  return value
}

/** The header to add to a raw request; empty before configureClient. */
export function clientHeaders(): Record<string, string> {
  return value ? { [CLIENT_HEADER]: value } : {}
}

/**
 * A WebSocket URL with `client=` added: a browser gives an upgrade no
 * headers, so the version goes in the query.
 */
export function withClientParam(url: string | URL): string {
  const out = new URL(url.toString(), typeof window !== 'undefined' ? window.location.href : 'http://localhost/')
  if (value) out.searchParams.set('client', value)
  return out.toString()
}

/** The error every request fails with once the server said this build is too old. */
export class ClientTooOldError extends Error {
  readonly code = 'clientTooOld'
  constructor() {
    super('This version of Kutup is too old for the server; reload the page.')
    this.name = 'ClientTooOldError'
  }
}

/** Whether the server refused this build as too old (latched until a reload). */
export function isClientTooOld(): boolean {
  return tooOld
}

/** Latches the refusal: every later request fails at once, and the page offers its reload. */
export function latchClientTooOld(): void {
  if (tooOld) return
  tooOld = true
  if (typeof window !== 'undefined') window.dispatchEvent(new Event(RELOAD_NEEDED_EVENT))
}

/** Forgets the latch (tests only). */
export function resetClientTooOld(): void {
  tooOld = false
}

/** Whether an HTTP status and body are the server's `clientTooOld`. */
export function isTooOldAnswer(status: number | undefined, code: unknown): boolean {
  return status === 426 && code === 'clientTooOld'
}

/**
 * `fetch` with this build's `X-Kutup-Client`, refusing at once once latched,
 * and latching a `426 clientTooOld` answer (which it then throws as
 * ClientTooOldError).
 */
export async function clientFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  if (tooOld) throw new ClientTooOldError()
  const headers = new Headers(init.headers)
  if (value && !headers.has(CLIENT_HEADER)) headers.set(CLIENT_HEADER, value)
  const response = await fetch(input, { ...init, headers })
  if (response.status === 426) {
    const body = (await response.clone().json().catch(() => null)) as { code?: unknown } | null
    if (isTooOldAnswer(response.status, body?.code)) {
      latchClientTooOld()
      throw new ClientTooOldError()
    }
  }
  return response
}
