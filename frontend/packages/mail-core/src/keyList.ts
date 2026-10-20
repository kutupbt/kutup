import {
  deriveAccountIdentityKeys,
  MAIL_KEY_FLAGS,
  signMailKeyList,
  toBase64,
  verifyMailKeyList,
  type MailKeyEntry,
  type SignedMailKeyList,
} from '@kutup/crypto'
import api from '@kutup/session/client'
import type { Session } from '@kutup/session/store'

// An address's signed key list (docs/plans/mail-address-keys.md), as this
// account changes it: the Account app's key page, and Mail's forwarding
// settings. Every next list is built from the current list this account
// signed, never from what the server says the keys are: a key, a primary or a
// flag the server lists on its own is reported and never signed into a list.
// Forwarding keys (docs/plans/mail-forwarding.md) are never in a list: they
// open only mail forwarded to the address and are never encrypted to.

/** One of an address's keys, as `GET /api/mail/addresses` lists it (the server's word). */
export interface ListedKey {
  fingerprint: string
  sha256Fingerprint: string
  primary: boolean
  flags: number
  /** A forwarding key: in no key list. */
  forwarding?: boolean
}

/** An address with its current key list, checked against this account's authority (null when it isn't this account's). */
export interface KeyListAddress {
  id: string
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

/**
 * Keys the server lists that the account's signed list doesn't have (or has
 * under another SHA-256 fingerprint). Forwarding keys are in no list, so
 * they're not among them.
 */
export function unlistedKeys<K extends ListedKey>(address: Pick<KeyListAddress, 'verifiedList'> & { keys: K[] }): K[] {
  return address.keys.filter((key) => {
    if (key.forwarding) return false
    const entry = signedEntry(address, key.fingerprint)
    return !entry || entry.sha256Fingerprint !== key.sha256Fingerprint
  })
}

/**
 * Whether the address's signed key list says not to encrypt to it
 * (`EMAIL_NO_ENCRYPT`): it forwards outside, and senders seal to it
 * zero-access so the server can re-send what arrives (as Proton's). False
 * without a list this account signed: the server's rows don't decide it.
 */
export function encryptionOff(address: Pick<KeyListAddress, 'verifiedList'>): boolean {
  return (address.verifiedList?.keys ?? []).some((key) => (key.flags & MAIL_KEY_FLAGS.emailNoEncrypt) !== 0)
}

/** `keys` with `EMAIL_NO_ENCRYPT` set (`on`) or cleared on every one. */
export function withEncryptionOff(keys: MailKeyEntry[], on: boolean): MailKeyEntry[] {
  return keys.map((key) => ({
    ...key,
    flags: on ? key.flags | MAIL_KEY_FLAGS.emailNoEncrypt : key.flags & ~MAIL_KEY_FLAGS.emailNoEncrypt,
  }))
}

/**
 * The next key list after the address's current one, with `keys`, signed by
 * this account. While the address forwards outside (its signed list says
 * so), every key keeps `EMAIL_NO_ENCRYPT` (the server refuses a list without
 * it).
 */
export async function nextKeyList(
  session: Pick<Session, 'masterKey'>,
  address: Pick<KeyListAddress, 'verifiedList'>,
  keys: MailKeyEntry[],
): Promise<SignedMailKeyList> {
  const current = address.verifiedList
  if (!current) throw new KeyListNotSigned()
  return signList(session, current, encryptionOff(address) ? withEncryptionOff(keys, true) : keys)
}

function signList(session: Pick<Session, 'masterKey'>, current: SignedMailKeyList, keys: MailKeyEntry[]): Promise<SignedMailKeyList> {
  return signMailKeyList(toBase64(session.masterKey), {
    address: current.address,
    sequence: current.sequence + 1,
    previousHash: current.hash,
    issuedAt: new Date().toISOString(),
    // Strictly by fingerprint (lowercase hex sorts as the bytes do).
    keys: [...keys].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1)),
  })
}

/**
 * The next key list with `EMAIL_NO_ENCRYPT` set on every key, the signed
 * list's keys otherwise: what an address's first outside forwarding brings
 * (`keyList` in `POST /api/mail/forwardings`).
 */
export async function encryptionOffList(session: Pick<Session, 'masterKey'>, address: Pick<KeyListAddress, 'verifiedList'>): Promise<SignedMailKeyList> {
  return nextKeyList(session, address, withEncryptionOff(signedEntries(address), true))
}

/**
 * The next key list with `EMAIL_NO_ENCRYPT` cleared, the signed list's keys
 * otherwise: end-to-end encryption back on, once the address's last outside
 * forwarding has ended (`keyListOwed`).
 */
export async function encryptionOnList(session: Pick<Session, 'masterKey'>, address: Pick<KeyListAddress, 'verifiedList'>): Promise<SignedMailKeyList> {
  const current = address.verifiedList
  if (!current) throw new KeyListNotSigned()
  return signList(session, current, withEncryptionOff(signedEntries(address), false))
}

/** One of the account's addresses as `GET /api/mail/addresses` lists it, with what key lists need. */
export interface AddressRow {
  id: string
  address: string
  state: 'active' | 'receiving' | 'closed' | 'freed'
  keys: (ListedKey & { id: string; publicKey: string; privateKeyEnvelope: string; createdAt: string })[]
  keyList: { data: string; signature: string } | null
  /** The last outside forwarding ended without this account's client: sign a list without `EMAIL_NO_ENCRYPT`. */
  keyListOwed?: boolean
}

/** An address with its key list checked against this account's own authority. */
export type CheckedAddress = AddressRow & { verifiedList: SignedMailKeyList | null }

/** `rows` with each current key list checked against this account's own authority (a list it didn't sign is null, not trusted). */
export async function checkedAddresses<T extends AddressRow>(
  session: Pick<Session, 'masterKey'>,
  rows: T[],
): Promise<(T & { verifiedList: SignedMailKeyList | null })[]> {
  const { authorityPublicKey } = await deriveAccountIdentityKeys(toBase64(session.masterKey))
  return Promise.all(
    rows.map(async (row) => ({
      ...row,
      verifiedList: row.keyList ? await verifyMailKeyList(row.keyList, authorityPublicKey).catch(() => null) : null,
    })),
  )
}

/**
 * Turns end-to-end encryption back on for each address whose last outside
 * forwarding ended without this account's client (declined, or deleted by
 * the forwardee): a key list without `EMAIL_NO_ENCRYPT`. True when any was
 * signed. It runs without a click, so it signs nothing but the flag: the
 * keys are the signed list's, and an address whose signed list has encryption
 * on already is left alone, whatever the server says. Another tab doing the
 * same is safe: the server takes the first list and refuses the second (409).
 */
export async function settleOwedKeyLists(session: Pick<Session, 'masterKey'>, rows: AddressRow[]): Promise<boolean> {
  const owed = rows.filter((row) => row.keyListOwed && row.keyList)
  if (owed.length === 0) return false
  let signed = false
  for (const address of await checkedAddresses(session, owed)) {
    if (!address.verifiedList || !encryptionOff(address)) continue
    const list = await encryptionOnList(session, address)
    try {
      await api.put(`/mail/addresses/${address.id}/key-list`, { keyList: { data: list.data, signature: list.signature } })
      signed = true
    } catch (error) {
      // Another device signed first, or a new outside forwarding began.
      if ((error as { response?: { status?: number } }).response?.status !== 409) throw error
    }
  }
  return signed
}
