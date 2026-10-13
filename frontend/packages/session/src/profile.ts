// Turn unlocked keys + a live access token into the app's Session.

import api from './client'
import type { SessionKeys } from './keys'
import { resetSessionVersion, setSessionVersionHandler } from './sessionVersion'
import { signOut } from './signOut'
import { clearSession, getSession, setAccessToken, setSession, updateSession } from './store'

export interface MeResponse {
  id: string
  /** The Kutup address. */
  address: string
  envelopeBinding: string
  username: string
  publicKey: string
  totpEnabled: boolean
  storageQuotaBytes: number
  storageUsedBytes: number
  isAdmin: boolean
  color: string
}

/** The signed-in account's profile, under `accessToken`. */
export async function fetchProfile(accessToken: string): Promise<MeResponse> {
  const { data } = await api.get<MeResponse>('/user/me', { headers: { Authorization: `Bearer ${accessToken}` } })
  return data
}

/**
 * The server named another key binding than the one this device verified:
 * the session is refused, and the person signs in again (a buggy or hostile
 * server must not make the apps seal under a key the account cannot open).
 */
export class KeyBindingMismatchError extends Error {
  constructor() {
    super('the server named another key binding than the account keys carry')
    this.name = 'KeyBindingMismatchError'
  }
}

/**
 * Publishes the session for `keys` to the app, with its profile (`me`, when
 * already fetched under the same token; loaded otherwise). The key binding
 * comes from `keys` (verified on this device), and `me` must name the same.
 */
export async function activateSession(
  keys: SessionKeys,
  accessToken: string,
  sessionId: string,
  prefetched?: MeResponse,
): Promise<void> {
  setAccessToken(accessToken)
  resetSessionVersion()
  const me = prefetched ?? (await api.get<MeResponse>('/user/me')).data
  if (me.id !== keys.userId) {
    throw new Error('the session belongs to a different account than its keys')
  }
  if (me.envelopeBinding !== keys.keyBinding) {
    // This sign-in is over: ended on the server too (best effort), and the
    // keys dropped here.
    await api.post('/auth/logout').catch(() => undefined)
    clearSession()
    keys.masterKey.fill(0)
    keys.privateKey.fill(0)
    throw new KeyBindingMismatchError()
  }
  setSession(
    {
      sessionId,
      userId: me.id,
      address: me.address,
      envelopeBinding: keys.keyBinding,
      username: me.username || null,
      isAdmin: me.isAdmin,
      storageQuotaBytes: me.storageQuotaBytes,
      storageUsedBytes: me.storageUsedBytes,
      totpEnabled: me.totpEnabled,
      color: me.color || null,
      publicKey: keys.publicKey,
      masterKey: keys.masterKey,
      privateKey: keys.privateKey,
      currentDeviceId: null,
    },
    accessToken,
  )
}

/**
 * The account's security state changed somewhere (docs/api.md, "Session
 * version"): read it again. Another key binding than this session's ends
 * it; otherwise the profile this app shows catches up (role, 2FA, name).
 */
export async function recheckAccount(): Promise<void> {
  const session = getSession()
  if (!session) return
  const { data: me } = await api.get<MeResponse>('/user/me')
  if (me.id !== session.userId || me.envelopeBinding !== session.envelopeBinding) {
    // As a refused session (KeyBindingMismatchError): ended on the server,
    // the keys dropped here; the app's boot shows "this account's keys
    // changed" on the way back.
    const { masterKey, privateKey } = session
    await signOut()
    masterKey.fill(0)
    privateKey.fill(0)
    return
  }
  updateSession({
    address: me.address,
    username: me.username || null,
    isAdmin: me.isAdmin,
    totpEnabled: me.totpEnabled,
  })
}

setSessionVersionHandler(recheckAccount)
