import { removeDevicesFromManifest } from '@kutup/crypto/accountManifest'
import { toBase64 } from '@kutup/crypto/base64'
import api from './client'
import { deviceHeader, ownAccount, publishNextManifest } from './devices'
import { clearPersisted } from './persistedStore'
import { broadcastLogout } from './sessionSync'
import { clearSession, getSession } from './store'

/** How long a sign-out waits for its device's removal. */
const REVOKE_WAIT_MS = 2000

/**
 * Takes this origin's device out of the account's manifest
 * (docs/plans/one-device-list.md): the next manifest without it, published
 * as itself. Best effort: ending the sign-in already marks its devices
 * expired and the next manifest drops them; this drops it at once, so
 * peers stop taking its frames. Skipped when it is the account's only
 * device (a manifest lists at least one).
 */
async function revokeOwnDevice(): Promise<void> {
  const session = getSession()
  const device = session?.device
  if (!session || !device || device.manifestSequence === 0n) return
  const masterKey = toBase64(session.masterKey)
  await publishNextManifest(await ownAccount(session), deviceHeader(device), async (head) => {
    if (!head?.devices.some((d) => d.deviceId === device.id) || head.devices.length < 2) return null
    return removeDevicesFromManifest(head, [device.id], new Date().toISOString(), masterKey)
  })
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
