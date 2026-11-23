// Mail's search index for an account, removed at sign-out
// (docs/plans/api-surface.md §6, decision 10). Its database is named by an
// HMAC under the account's object-id key, computed here while the session
// still holds it. Registered by the Mail app at boot.

import { registerSignOutCleanup } from '@kutup/session/signOut'
import type { Session } from '@kutup/session/store'
import { mailSearchStoreName } from './searchWasm'

export async function forgetMailSearch(session: Pick<Session, 'roots'>): Promise<void> {
  if (typeof indexedDB === 'undefined') return
  const name = `kutup.mail.search:${await mailSearchStoreName(session.roots.objectIdKey)}`
  await new Promise<void>((resolve) => {
    const request = indexedDB.deleteDatabase(name)
    request.onsuccess = () => resolve()
    request.onerror = () => resolve()
    // Open in this tab or another: it closes on the version change and the
    // delete goes through then.
    request.onblocked = () => resolve()
  })
}

export function registerMailSignOutCleanup(): void {
  registerSignOutCleanup(forgetMailSearch)
}
