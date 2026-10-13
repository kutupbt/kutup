// Turn unlocked keys + a live access token into the app's Session.

import api from './client'
import type { SessionKeys } from './keys'
import { resetSessionVersion, setSessionVersionHandler } from './sessionVersion'
import { signOut } from './signOut'
import { getSession, setAccessToken, setSession, updateSession } from './store'

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
 * Publishes the session for `keys` to the app, with its profile (`me`, when
 * already fetched under the same token; loaded otherwise).
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
  setSession(
    {
      sessionId,
      userId: me.id,
      address: me.address,
      envelopeBinding: me.envelopeBinding,
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
    await signOut()
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
