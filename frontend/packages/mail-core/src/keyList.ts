import { signMailKeyList, toBase64, type MailKeyEntry, type SignedMailKeyList } from '@kutup/crypto'
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
