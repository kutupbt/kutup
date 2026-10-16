import { accountKey, parseAccount, type AccountRef } from '@kutup/chat-core/identity'
import { nameOfAccount } from '@kutup/drive-core/accountName'
import { driveIdentityOf, type DriveIdentity } from '@kutup/drive-core/identity'
import type { Session } from '@kutup/session/store'

// What to call an account that has no Chat profile name (yet): Chat keys
// people by account (docs/plans/account-ids.md), and an account is never
// shown by its key. As Signal shows a username for an account without a
// profile, this shows an address: the one the account's own signed rename
// chain proves or it was first met at (the account's identity pins), else
// the one its server says it has now. Looked up once per account and asked
// again a while later, so a pin made since (another app, another device)
// takes over from the server's label; the chat store re-renders when a name
// arrives.

/** A name found is asked for again after this long; a failed lookup sooner. */
const FRESH_MS = 5 * 60_000
const RETRY_MS = 30_000

interface Entry {
  name: string | null
  /** When to ask again. */
  until: number
  pending: boolean
}

let me: Promise<DriveIdentity> | null = null
let changed: () => void = () => {}
const names = new Map<string, Entry>()
/** Addresses an account was found at that belong to someone else the user knows: never its name. */
const distrusted = new Map<string, Set<string>>()

/** Starts over for a signed-in session; `onChange` runs when a name arrives. */
export function startAccountNames(session: Session, onChange: () => void): void {
  me = driveIdentityOf(session)
  me.catch(() => {})
  changed = onChange
  names.clear()
  distrusted.clear()
}

/** This account's identity for the shared pin list, once Chat is open. */
export function driveIdentity(): Promise<DriveIdentity> | null {
  return me
}

export function stopAccountNames(): void {
  me = null
  changed = () => {}
  names.clear()
  distrusted.clear()
}

/**
 * `account` was found at `address`, which someone else the user knows holds:
 * the account is never shown by it (a server's label for it may say so).
 */
export function distrustAddress(account: AccountRef, address: string): void {
  const key = accountKey(account)
  const set = distrusted.get(key) ?? new Set<string>()
  set.add(address.toLowerCase())
  distrusted.set(key, set)
  names.delete(key)
}

/**
 * The address to show for the account `key` (`aci:<uuid>@<server>`), or
 * null while it is looked up or when nobody can say.
 */
export function accountName(key: string, now = Date.now()): string | null {
  const known = names.get(key)
  if (known && (known.pending || now < known.until)) return known.name
  const account = parseAccount(key)
  if (!account || !me) return known?.name ?? null
  const entry: Entry = { name: known?.name ?? null, until: now + RETRY_MS, pending: true }
  names.set(key, entry)
  const lookup = me
  void lookup
    .then((identity) => nameOfAccount(identity, account))
    .then(
      (found) => {
        if (me !== lookup) return
        const name = found && !distrusted.get(key)?.has(found.toLowerCase()) ? found : null
        names.set(key, { name: name ?? entry.name, until: Date.now() + (name ? FRESH_MS : RETRY_MS), pending: false })
        if (name && name !== entry.name) changed()
      },
      () => {
        if (me === lookup) names.set(key, { ...entry, until: Date.now() + RETRY_MS, pending: false })
      },
    )
  return entry.name
}

/** Test seam: names as if looked up, fresh for a while. */
export function setAccountNamesForTesting(entries: Iterable<[string, string]>): void {
  names.clear()
  for (const [key, name] of entries) names.set(key, { name, until: Date.now() + FRESH_MS, pending: false })
}
