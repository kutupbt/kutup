import { parseAccount } from '@kutup/chat-core/identity'
import { nameOfAccount } from '@kutup/drive-core/accountName'
import { driveIdentityOf, type DriveIdentity } from '@kutup/drive-core/identity'
import type { Session } from '@kutup/session/store'

// What to call an account that has no Chat profile name (yet): Chat keys
// people by account (docs/plans/account-ids.md), and an account is never
// shown by its key. As Signal shows a username for an account without a
// profile, this shows an address: the one the account's own signed rename
// chain proves or it was first met at (the account's identity pins), else
// the one its server says it has now. Looked up once per account and page;
// the chat store re-renders when one arrives.

let me: Promise<DriveIdentity> | null = null
let changed: () => void = () => {}
const names = new Map<string, string | null>()

/** Starts over for a signed-in session; `onChange` runs when a name arrives. */
export function startAccountNames(session: Session, onChange: () => void): void {
  me = driveIdentityOf(session)
  me.catch(() => {})
  changed = onChange
  names.clear()
}

/** This account's identity for the shared pin list, once Chat is open. */
export function driveIdentity(): Promise<DriveIdentity> | null {
  return me
}

export function stopAccountNames(): void {
  me = null
  changed = () => {}
  names.clear()
}

/**
 * The address to show for the account `key` (`aci:<uuid>@<server>`), or
 * null while it is looked up or when nobody can say.
 */
export function accountName(key: string): string | null {
  if (names.has(key)) return names.get(key) ?? null
  const account = parseAccount(key)
  if (!account || !me) return null
  names.set(key, null)
  const lookup = me
  void lookup
    .then((identity) => nameOfAccount(identity, account))
    .then((name) => {
      if (me !== lookup || !name) return
      names.set(key, name)
      changed()
    })
    .catch(() => {})
  return null
}

/** Test seam: names as if looked up. */
export function setAccountNamesForTesting(entries: Iterable<[string, string]>): void {
  names.clear()
  for (const [key, name] of entries) names.set(key, name)
}
