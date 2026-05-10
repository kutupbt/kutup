// Shared API error types. Thrown from the api/* helpers when a backend
// response needs distinct handling at the call site (e.g. localized toast,
// disarmed autosave) rather than a generic axios error.

/** Thrown by api/* helpers when the backend returns 413 (storage quota
 *  exceeded). Distinct type so callers can localize / disarm retries
 *  instead of surfacing the raw English error string. */
export class QuotaExceededError extends Error {
  constructor() {
    super('storage quota exceeded')
    this.name = 'QuotaExceededError'
  }
}
