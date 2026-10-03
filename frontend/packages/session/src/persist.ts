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
import { getCryptoWasm } from '@kutup/crypto/rustWasm'
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

function ended(): RestoreResult {
  clearPersisted()
  return 'none'
}

/**
 * Restore the session from this origin's blob: refresh the cookie, fetch the
 * local key, open the blob.
 *
 * The blob is deleted only on a definite answer: the server says the session
 * is over, the blob belongs to another session, or it does not authenticate
 * under its key. Anything else — the server unreachable, the WASM runtime
 * failing to load, the page being navigated away mid-request — is rethrown
 * with the blob intact, so it never costs anybody their sign-in.
 */
export async function restoreSession(): Promise<RestoreResult> {
  const persisted = readPersisted()
  if (!persisted) return 'none'

  let refreshed: Awaited<ReturnType<typeof refreshAccessToken>>
  try {
    refreshed = await refreshAccessToken()
  } catch (error) {
    if (sessionEnded(error)) return ended()
    throw error
  }
  const { accessToken, sessionId } = refreshed
  if (sessionId !== persisted.sessionId) return ended()

  let localKey: Uint8Array
  try {
    const { data } = await api.get<{ key: string }>('/auth/sessions/current/local-key', {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
    localKey = fromBase64(data.key)
  } catch (error) {
    if (sessionEnded(error)) return ended()
    throw error
  }

  // Load the runtime first, so a failed load is not mistaken for a bad blob.
  await getCryptoWasm()
  let keys: SessionKeys
  try {
    const plaintext = await openLocalState(
      persisted.blob,
      localKey,
      LocalStatePurpose.WebSession,
      profileFor(sessionId),
    )
    keys = decodeKeys(plaintext)
    plaintext.fill(0)
  } catch {
    return ended()
  } finally {
    localKey.fill(0)
  }

  await activateSession(keys, accessToken, sessionId)
  return 'restored'
}
