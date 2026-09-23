// Where an app origin keeps its encrypted session blob (see ./persist). Kept
// free of API imports so the client can wipe it when a session ends.

export const PERSISTED_SESSION_KEY = 'kutup-session'

export interface PersistedSession {
  v: 1
  sessionId: string
  userId: string
  /** A WebSession local-state envelope; its key is held by the server. */
  blob: string
}

export function readPersisted(): PersistedSession | null {
  try {
    const raw = localStorage.getItem(PERSISTED_SESSION_KEY)
    if (!raw) return null
    const value = JSON.parse(raw) as Partial<PersistedSession>
    if (
      value.v !== 1 ||
      typeof value.sessionId !== 'string' ||
      typeof value.userId !== 'string' ||
      typeof value.blob !== 'string'
    ) {
      return null
    }
    return value as PersistedSession
  } catch {
    return null
  }
}

export function writePersisted(value: PersistedSession): void {
  localStorage.setItem(PERSISTED_SESSION_KEY, JSON.stringify(value))
}

export function clearPersisted(): void {
  try {
    localStorage.removeItem(PERSISTED_SESSION_KEY)
  } catch {
    // Storage unavailable: there is nothing persisted to clear.
  }
}
