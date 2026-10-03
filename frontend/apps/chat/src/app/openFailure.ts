import { isAxiosError } from 'axios'

/**
 * Whether Chat failed to open because the server could not be reached or
 * could not answer (offline, a timeout, 5xx, rate limiting), as opposed to
 * something wrong with this browser's own Chat data.
 *
 * The difference decides what the person is offered. An unreachable server
 * is waited out: Chat retries by itself. Only a failure of the browser's own
 * state offers "Repair this browser", which discards its Chat device; taken
 * during a mere outage it replaces a healthy device for nothing.
 */
export function isServerUnreachable(error: unknown): boolean {
  if (typeof navigator !== 'undefined' && navigator.onLine === false) return true
  if (isAxiosError(error)) return transientStatus(error.response?.status)
  // The engine reports its own requests as "transport: <what failed>".
  const text = error instanceof Error ? error.message : String(error)
  if (!/^transport:/i.test(text)) return false
  const status = /status code (\d{3})\b/.exec(text)
  return transientStatus(status ? Number(status[1]) : undefined)
}

/** No answer at all, or one that says "not now". */
function transientStatus(status: number | undefined): boolean {
  return status === undefined || status >= 500 || status === 429 || status === 408
}

/** Seconds before each automatic attempt to open Chat again, then the last. */
export const REOPEN_DELAYS_MS = [2_000, 4_000, 8_000, 15_000, 30_000] as const
