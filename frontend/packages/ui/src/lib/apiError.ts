import { AxiosError } from 'axios'

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
 * A message worth showing. The server's 4xx message is preferred: it is the
 * only party that knows why a request was refused. `fallback` covers network
 * failures, 5xx (generic by design) and bodies that are not our shape.
 */
export function apiErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof AxiosError) {
    const status = error.response?.status ?? 0
    const body: unknown = error.response?.data
    if (status >= 400 && status < 500 && isApiErrorBody(body) && body.error.trim() !== '') {
      return body.error
    }
  }
  return fallback
}
