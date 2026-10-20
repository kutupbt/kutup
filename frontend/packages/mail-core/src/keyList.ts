import {
  deriveAccountIdentityKeys,
  foldAddress,
  inspectMailAddressPublicKey,
  signMailKeyList,
  toBase64,
  verifyMailKeyList,
  type MailKeyEntry,
  type SignedMailKeyList,
} from '@kutup/crypto'
import { OlderThanSeenError, revisionGuard } from '@kutup/crypto/revisionGuard'
import type { Session } from '@kutup/session/store'

// An address's signed key list (docs/plans/mail-address-keys.md), as this
// account changes it. Every next list is built from the current list this
// account signed, never from what the server says the keys are: a key, a
// primary or a flag the server lists on its own is reported and never signed
// into a list.

/** One of an address's keys, as `GET /api/mail/addresses` lists it (the server's word). */
export interface ListedKey {
  fingerprint: string
  sha256Fingerprint: string
  primary: boolean
  flags: number
}

/** An address with its current key list, checked against this account's authority (null when it isn't this account's). */
export interface KeyListAddress {
  address: string
  keys: ListedKey[]
  verifiedList: SignedMailKeyList | null
}

/** The address's current key list isn't signed by this account: nothing can be built on it. */
export class KeyListNotSigned extends Error {
  constructor() {
    super('the current key list is not signed by this account')
  }
}

/** The keys of the address's current list, as this account signed them. */
export function signedEntries(address: Pick<KeyListAddress, 'verifiedList'>): MailKeyEntry[] {
  if (!address.verifiedList) throw new KeyListNotSigned()
  return address.verifiedList.keys.map((key) => ({ ...key }))
}

/** The signed entry of the key `fingerprint`, if the current list has it. */
export function signedEntry(address: Pick<KeyListAddress, 'verifiedList'>, fingerprint: string): MailKeyEntry | undefined {
  return address.verifiedList?.keys.find((key) => key.fingerprint === fingerprint)
}

/** Keys the server lists that the account's signed list doesn't have (or has under another SHA-256 fingerprint). */
export function unlistedKeys<K extends ListedKey>(address: Pick<KeyListAddress, 'verifiedList'> & { keys: K[] }): K[] {
  return address.keys.filter((key) => {
    const entry = signedEntry(address, key.fingerprint)
    return !entry || entry.sha256Fingerprint !== key.sha256Fingerprint
  })
}

/** The next key list after the address's current one, with `keys`, signed by this account. */
export async function nextKeyList(
  session: Pick<Session, 'masterKey'>,
  address: Pick<KeyListAddress, 'verifiedList'>,
  keys: MailKeyEntry[],
): Promise<SignedMailKeyList> {
  const current = address.verifiedList
  if (!current) throw new KeyListNotSigned()
  return signMailKeyList(toBase64(session.masterKey), {
    address: current.address,
    sequence: current.sequence + 1,
    previousHash: current.hash,
    issuedAt: new Date().toISOString(),
    // Strictly by fingerprint (lowercase hex sorts as the bytes do).
    keys: [...keys].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1)),
  })
}

/** What the revision guard calls an address's key list (the same count `keys.ts` keeps for recipients). */
export const KEY_LIST_GUARD_SCOPE = 'mail-key-list'

/** The address's own key list is older than one this device has seen: the server went back. */
export class OwnKeyListRolledBack extends Error {
  constructor(readonly address: string) {
    super(`the key list of ${address} is older than one this device has seen`)
  }
}

/** A row of `GET /api/mail/addresses` as far as checking it needs. */
interface OwnRow<K> {
  address: string
  keys: K[]
  keyList: { data: string; signature: string } | null
}

/** A server key row, with whether the account's signed list names it (`listed`): its public key's own fingerprints, not the row's word. */
export type CheckedKey<K> = K & { listed: boolean }

/**
 * `rows` checked against this account's own authority (derived from the
 * master key, never the server's word): each current key list must verify,
 * name the row's address (folded), and be no older than one this device has
 * seen for it; a list that fails is null (`verifiedList`), not trusted. Each
 * key row is `listed` only when its public key, inspected here, has the
 * fingerprints a signed entry names: only those may be encrypted to, shown
 * as the account's, or downloaded. A list older than one seen throws
 * `OwnKeyListRolledBack` when `strict`, else is null.
 */
export async function checkedAddresses<T extends OwnRow<ListedKey & { publicKey: string }>>(
  session: Pick<Session, 'masterKey' | 'userId'>,
  rows: T[],
  options: { strict?: boolean } = {},
): Promise<(Omit<T, 'keys'> & { keys: CheckedKey<T['keys'][number]>[]; verifiedList: SignedMailKeyList | null })[]> {
  const { authorityPublicKey } = await deriveAccountIdentityKeys(toBase64(session.masterKey))
  const checked = []
  for (const row of rows) {
    const verifiedList = await ownList(session, authorityPublicKey, row, options.strict ?? false)
    const keys = await Promise.all(
      row.keys.map(async (key) => ({ ...key, listed: verifiedList ? await namedBy(verifiedList, row.address, key) : false })),
    )
    checked.push({ ...row, keys, verifiedList })
  }
  return checked
}

async function ownList(
  session: Pick<Session, 'masterKey' | 'userId'>,
  authorityPublicKey: string,
  row: OwnRow<unknown>,
  strict: boolean,
): Promise<SignedMailKeyList | null> {
  if (!row.keyList) return null
  const list = await verifyMailKeyList(row.keyList, authorityPublicKey).catch(() => null)
  if (!list) return null
  // The list must be this row's address's, not another one of the account's.
  const folded = await foldAddress(row.address)
  if (!folded || folded !== (await foldAddress(list.address))) return null
  try {
    await revisionGuard(session).accept(KEY_LIST_GUARD_SCOPE, `${folded}:${authorityPublicKey}`, list.sequence)
  } catch (error) {
    if (!(error instanceof OlderThanSeenError)) throw error
    if (strict) throw new OwnKeyListRolledBack(row.address)
    return null
  }
  return list
}

/** Whether `key`'s public key is one the signed list names (its fingerprints, as inspected here). */
async function namedBy(list: SignedMailKeyList, address: string, key: ListedKey & { publicKey: string }): Promise<boolean> {
  const entry = list.keys.find((listed) => listed.fingerprint === key.fingerprint)
  if (!entry || entry.sha256Fingerprint !== key.sha256Fingerprint) return false
  const info = await inspectMailAddressPublicKey(key.publicKey, address).catch(() => null)
  return !!info && info.fingerprint === entry.fingerprint && info.sha256Fingerprint === entry.sha256Fingerprint
}

/** Signed entries no server row carries with a matching public key: the server dropped (or swapped) a key the account signed. */
export function missingKeys(address: { keys: { fingerprint: string; listed: boolean }[]; verifiedList: SignedMailKeyList | null }): MailKeyEntry[] {
  return (address.verifiedList?.keys ?? []).filter((entry) => !address.keys.some((key) => key.listed && key.fingerprint === entry.fingerprint))
}
