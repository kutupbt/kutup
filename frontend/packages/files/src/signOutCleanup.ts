// What this package keeps per account on an origin, removed at sign-out
// (docs/plans/api-surface.md §6, decision 10): the account's ciphertext
// cache entries and its interrupted uploads. Apps that use this package
// register it at boot (registerFilesSignOutCleanup in their main.tsx).

import { registerSignOutCleanup } from '@kutup/session/signOut'
import type { Session } from '@kutup/session/store'
import { purgePrivateCiphertextCacheForAccountV1 } from './mediaCache/registry'
import { pendingUploads } from './upload/pendingUploads'

export async function forgetFilesForAccount(session: Pick<Session, 'accountId'>): Promise<void> {
  await Promise.all([
    purgePrivateCiphertextCacheForAccountV1(session.accountId),
    pendingUploads.removeOwner(session.accountId),
  ])
}

export function registerFilesSignOutCleanup(): void {
  registerSignOutCleanup(forgetFilesForAccount)
}
