// Turn unlocked keys + a live access token into the app's Session.

import api from './client'
import type { SessionKeys } from './keys'
import { setAccessToken, setSession } from './store'

interface MeResponse {
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

/** Loads the profile for `keys` and publishes the session to the app. */
export async function activateSession(
  keys: SessionKeys,
  accessToken: string,
  sessionId: string,
): Promise<void> {
  setAccessToken(accessToken)
  const { data: me } = await api.get<MeResponse>('/user/me')
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
