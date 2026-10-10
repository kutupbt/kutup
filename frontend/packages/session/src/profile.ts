// Turn unlocked keys + a live access token into the app's Session.

import api from './client'
import type { SessionKeys } from './keys'
import { setAccessToken, setSession } from './store'

export interface MeResponse {
  id: string
  email: string
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
  const me = prefetched ?? (await api.get<MeResponse>('/user/me')).data
  if (me.id !== keys.userId) {
    throw new Error('the session belongs to a different account than its keys')
  }
  setSession(
    {
      sessionId,
      userId: me.id,
      email: me.email,
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
