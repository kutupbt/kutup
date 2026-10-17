import { toBase64 } from '@kutup/crypto/base64'
import { signDeviceRevocation } from '@kutup/crypto/deviceRegistration'
import api from './client'
import { clearPersisted } from './persistedStore'
import { broadcastLogout } from './sessionSync'
import { clearSession, getSession } from './store'

/** How long a sign-out waits for its device's revocation. */
const REVOKE_WAIT_MS = 2000

/**
 * Revokes this origin's collaboration device for good, signed by the account
 * (docs/plans/device-registration.md). Best effort: ending the sign-in
 * already retires it on the server; this also makes its key unusable
 * anywhere, even if a copy of it survived.
 */
async function revokeOwnDevice(): Promise<void> {
  const session = getSession()
  const device = session?.device
  if (!session || !device) return
  const at = session.address.lastIndexOf('@')
  if (at < 0) return
  const revokedAtMs = Date.now()
  const signature = await signDeviceRevocation(
    toBase64(session.masterKey),
    session.address.slice(at + 1),
    toBase64(device.publicKey),
    revokedAtMs,
  )
  await api.delete(`/devices/${device.id}`, { data: { revokedAtMs, signature }, timeout: REVOKE_WAIT_MS })
}

/**
 * Sign out of Kutup from any app: the server ends the whole sign-in (the
 * account session and every app session forked from it), then this origin's
 * tabs drop their keys. Other apps notice on their next request. Local state
 * is cleared even when the server cannot be reached; the return value says
 * whether the server confirmed.
 */
export async function signOut(): Promise<boolean> {
  let confirmed = false
  await Promise.race([
    revokeOwnDevice().catch(() => undefined),
    new Promise((resolve) => setTimeout(resolve, REVOKE_WAIT_MS)),
  ])
  try {
    await api.post('/auth/logout')
    confirmed = true
  } catch {
    // Unreachable or already ended: the local sign-out still happens.
  }
  broadcastLogout()
  clearPersisted()
  clearSession()
  clearAccountLists()
  return confirmed
}

/**
 * Lists this origin keeps per account in localStorage (the Chat and Mail
 * "not in contacts" dismissals): gone with the sign-in, and the old
 * unkeyed copies with them.
 */
const ACCOUNT_LISTS = /^kutup\.(chat|mail)\.notInContactsDismissed(:|$)/

export function clearAccountLists(): void {
  try {
    const doomed: string[] = []
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i)
      if (key && ACCOUNT_LISTS.test(key)) doomed.push(key)
    }
    for (const key of doomed) localStorage.removeItem(key)
  } catch {
    // Storage blocked: nothing kept to clear.
  }
}
