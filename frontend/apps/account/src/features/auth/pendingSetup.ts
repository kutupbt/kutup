import type { PendingSetup } from './flows'

// An administrator-created account between "temporary password accepted" and
// "keys generated". Memory only: the setup token authenticates key creation,
// so it must not outlive the tab in storage or history. A reload means
// signing in again with the temporary password.
let pending: PendingSetup | null = null

export function setPendingSetup(value: PendingSetup | null): void {
  pending = value
}

export function getPendingSetup(): PendingSetup | null {
  return pending
}
