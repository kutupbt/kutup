import { AxiosError } from 'axios'
import { getI18n } from 'react-i18next'

/**
 * The error body every kutup-server handler returns: `{ "error": "<message>" }`.
 * 5xx responses carry a generic message only (the cause is logged server-side).
 */
export interface ApiErrorBody {
  error: string
}

export type ApiErrorCode =
  | 'bad_request'
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'payload_too_large'
  | 'too_many_requests'
  | 'internal'
  | 'network'

function isApiErrorBody(value: unknown): value is ApiErrorBody {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as ApiErrorBody).error === 'string'
  )
}

/** A machine-readable code derived from the HTTP status, or `network`. */
export function apiErrorCode(error: unknown): ApiErrorCode | null {
  if (!(error instanceof AxiosError)) return null
  const status = error.response?.status
  if (status === undefined) return 'network'
  switch (status) {
    case 400:
    case 422:
      return 'bad_request'
    case 401:
      return 'unauthenticated'
    case 403:
      return 'forbidden'
    case 404:
      return 'not_found'
    case 409:
      return 'conflict'
    case 413:
      return 'payload_too_large'
    case 429:
      return 'too_many_requests'
    default:
      return 'internal'
  }
}

/**
 * Refusals whose `code` has its own words in every language, wherever they
 * come from (the server's message is English): the post-quantum Drive key
 * upgrade (docs/plans/pq-shares.md).
 */
const CODE_MESSAGES: Record<string, string> = {
  keysPendingUpgrade: 'apiErrors.keysPendingUpgrade',
  peerOutdated: 'apiErrors.peerOutdated',
}

/** `value`'s message for its `code`: a server body, or a client error that stops before asking. */
function codeMessage(value: unknown): string | null {
  const code = typeof value === 'object' && value !== null ? (value as { code?: unknown }).code : undefined
  const key = typeof code === 'string' ? CODE_MESSAGES[code] : undefined
  const i18n = key ? getI18n() : undefined
  return key && i18n?.exists(key) ? i18n.t(key) : null
}

/**
 * A message worth showing. A refusal with a known code says it in the user's
 * language; otherwise the server's 4xx message is preferred: it is the only
 * party that knows why a request was refused. `fallback` covers network
 * failures, 5xx (generic by design) and bodies that are not our shape.
 */
export function apiErrorMessage(error: unknown, fallback: string): string {
  if (!(error instanceof AxiosError)) return codeMessage(error) ?? fallback
  const status = error.response?.status ?? 0
  const body: unknown = error.response?.data
  const coded = codeMessage(body)
  if (coded) return coded
  if (status >= 400 && status < 500 && isApiErrorBody(body) && body.error.trim() !== '') {
    return body.error
  }
  return fallback
}
