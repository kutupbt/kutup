import api from './client'
import { clearPersisted } from './persistedStore'
import { broadcastLogout } from './sessionSync'
import { clearSession } from './store'

/**
 * Sign out of Kutup from any app: the server ends the whole sign-in (the
 * account session and every app session forked from it), then this origin's
 * tabs drop their keys. Other apps notice on their next request. Local state
 * is cleared even when the server cannot be reached; the return value says
 * whether the server confirmed.
 */
export async function signOut(): Promise<boolean> {
  let confirmed = false
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
