// Keep an app origin signed in across reloads and new tabs without keeping
// usable keys in the browser.
//
// The keys are sealed into a WebSession local-state envelope (profile
// `<client>:<session id>`) under a random 32-byte local key. The envelope is
// stored in localStorage; the local key is stored only on the server
// (`/api/auth/sessions/current/local-key`) and released only to this live
// session. Neither half is useful alone, and revoking the session — sign-out,
// "sign out everywhere", a password reset — makes the blob useless.

import { isAxiosError } from 'axios'
import { toBase64, fromBase64 } from '@kutup/crypto/base64'
import { LocalStatePurpose, openLocalState, sealLocalState } from '@kutup/crypto/localState'
import api, { getClientType, refreshAccessToken } from './client'
import { decodeKeys, encodeKeys, type SessionKeys } from './keys'
import { activateSession } from './profile'
import { clearPersisted, readPersisted, writePersisted } from './persistedStore'

function profileFor(sessionId: string): string {
  return `${getClientType()}:${sessionId}`
}

/** Seal and store `keys` for this origin's current session. */
export async function persistKeys(sessionId: string, keys: SessionKeys): Promise<void> {
  const localKey = crypto.getRandomValues(new Uint8Array(32))
  try {
    await api.put('/auth/sessions/current/local-key', { key: toBase64(localKey) })
    const blob = await sealLocalState(
      encodeKeys(keys),
      localKey,
      LocalStatePurpose.WebSession,
      profileFor(sessionId),
    )
    writePersisted({ v: 1, sessionId, userId: keys.userId, blob })
  } finally {
    localKey.fill(0)
  }
}

export type RestoreResult = 'restored' | 'none'

/** The server says this sign-in is over (as opposed to being unreachable). */
function sessionEnded(error: unknown): boolean {
  if (!isAxiosError(error)) return false
  const status = error.response?.status
  return status === 401 || status === 403 || status === 404
}

/**
 * Restore the session from this origin's blob: refresh the cookie, fetch the
 * local key, open the blob.
 *
 * Reports `none` (and clears the blob) when there is nothing to restore: no
 * blob, an ended session, a blob from another session or one that does not
 * open. Network and server failures are rethrown with the blob intact, so a
 * flaky connection does not sign anybody out.
 */
export async function restoreSession(): Promise<RestoreResult> {
  const persisted = readPersisted()
  if (!persisted) return 'none'
  try {
    const { accessToken, sessionId } = await refreshAccessToken()
    if (sessionId !== persisted.sessionId) {
      clearPersisted()
      return 'none'
    }
    const { data } = await api.get<{ key: string }>('/auth/sessions/current/local-key', {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
    const localKey = fromBase64(data.key)
    let plaintext: Uint8Array
    try {
      plaintext = await openLocalState(
        persisted.blob,
        localKey,
        LocalStatePurpose.WebSession,
        profileFor(sessionId),
      )
    } finally {
      localKey.fill(0)
    }
    const keys = decodeKeys(plaintext)
    plaintext.fill(0)
    await activateSession(keys, accessToken, sessionId)
    return 'restored'
  } catch (error) {
    if (isAxiosError(error) && !sessionEnded(error)) throw error
    clearPersisted()
    return 'none'
  }
}
