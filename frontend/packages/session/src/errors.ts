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

/** A file's metadata as the server has it now: what a save seals on top of after a conflict. */
export interface CurrentMetadata {
  metadataRevision: number
  metadataEnvelope: string
}

/**
 * A save's metadata lost to someone else's (`409 revisionConflict`):
 * `current` is the file's metadata as it is now, when the server sent it,
 * so the save seals on top of it and tries again.
 */
export class MetadataConflictError extends Error {
  constructor(readonly current: CurrentMetadata | null) {
    super('the file changed since')
    this.name = 'MetadataConflictError'
  }
}
