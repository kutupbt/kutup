import type { PendingRebind } from './flows'

// An account signed in whose keys are still bound to its old sign-in email,
// between the sign-in and the re-seal (docs/plans/account-identity.md).
// Memory only: it holds the password's key-encryption key and login key, so
// it must not outlive the tab; a reload drops it and the re-seal is offered
// again at the next sign-in.
let pending: PendingRebind | null = null

export function setPendingRebind(value: PendingRebind | null): void {
  pending?.keyEncryptionKey.fill(0)
  pending = value
}

export function getPendingRebind(): PendingRebind | null {
  return pending
}
