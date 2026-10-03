// The signed-in session of this app origin.
//
// A tiny external store (no Redux): the axios client and the logic packages
// read it synchronously, React reads it through `useSession()`
// (useSyncExternalStore). Key material lives in memory only; persistence
// across reloads is the job of the encrypted per-origin session blob, not of
// this module.

import { useSyncExternalStore } from 'react'

export interface Session {
  /** The server-side session (auth_sessions.id) this app origin holds. */
  sessionId: string
  userId: string
  email: string
  username: string | null
  isAdmin: boolean
  storageQuotaBytes: number
  storageUsedBytes: number
  totpEnabled: boolean
  /** Collab presence colour `#rrggbb`, or null for the deterministic default. */
  color: string | null
  publicKey: string
  masterKey: Uint8Array
  privateKey: Uint8Array
  currentDeviceId: number | null
}

interface State {
  session: Session | null
  accessToken: string | null
}

let state: State = { session: null, accessToken: null }
const listeners = new Set<() => void>()

function emit(next: State) {
  state = next
  for (const l of listeners) l()
}

export function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function getSession(): Session | null {
  return state.session
}

export function getAccessToken(): string | null {
  return state.accessToken
}

export function setSession(session: Session, accessToken: string): void {
  emit({ session, accessToken })
}

export function updateSession(patch: Partial<Session>): void {
  if (!state.session) return
  emit({ ...state, session: { ...state.session, ...patch } })
}

export function setAccessToken(accessToken: string): void {
  emit({ ...state, accessToken })
}

export function clearSession(): void {
  const prev = state.session
  emit({ session: null, accessToken: null })
  // Best-effort hygiene; the threat model assumes a hostile device wins.
  prev?.masterKey.fill(0)
  prev?.privateKey.fill(0)
}

/** The current session, or null when signed out. */
export function useSession(): Session | null {
  return useSyncExternalStore(subscribe, getSession, getSession)
}

/** The current session; throws when signed out. Use under an auth guard. */
export function useRequiredSession(): Session {
  const session = useSession()
  if (!session) throw new Error('useRequiredSession() outside a signed-in route')
  return session
}
