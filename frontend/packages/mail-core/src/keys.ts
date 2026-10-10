import { fromBase64, inspectExternalMailKey, inspectMailAddressPublicKey, MAIL_KEY_FLAGS, verifyMailKeyList, type SignedMailKeyList } from '@kutup/crypto'
import api from '@kutup/session/client'

// A Kutup address's public keys (docs/plans/mail-address-keys.md), checked
// before anything is encrypted to them or a signature is trusted: every key
// list in the chain is signed by the account's authority and follows the one
// before, and the keys the server hands out are the ones the newest list
// names.

interface PublicKeyRow {
  fingerprint: string
  sha256Fingerprint: string
  publicKey: string
  primary: boolean
  flags: number
}

interface KeyLookup {
  address: string
  account: string
  accountAuthorityPublicKey: string
  keys: PublicKeyRow[]
  keyLists: { data: string; signature: string }[]
}

export interface AddressKeys {
  address: string
  account: string
  authorityPublicKey: string
  /** The key to encrypt to (base64). */
  primary: string
  /** Every key the newest list trusts for signatures (not marked compromised), primary first. */
  all: string[]
}

/** The address is not a Kutup address (or has no key yet). */
export class NoKutupAddress extends Error {
  constructor(readonly address: string) {
    super(`${address} has no Kutup mail key`)
  }
}

/** The server's keys do not match what the account signed. */
export class UnverifiedKeys extends Error {
  constructor(readonly address: string) {
    super(`the keys of ${address} do not match their signed key list`)
  }
}

const cache = new Map<string, Promise<AddressKeys>>()

/** Forgets what was looked up, after a key-changed answer. */
export function forgetKeys(address?: string) {
  if (address) cache.delete(address.toLowerCase())
  else cache.clear()
}

async function load(address: string): Promise<AddressKeys> {
  let lookup: KeyLookup
  try {
    lookup = (await api.get<KeyLookup>('/mail/keys', { params: { email: address } })).data
  } catch (error) {
    if ((error as { response?: { status?: number } }).response?.status === 404) throw new NoKutupAddress(address)
    throw error
  }
  let previous: { data: string; signature: string } | undefined
  let newest: SignedMailKeyList | null = null
  for (const list of lookup.keyLists) {
    newest = await verifyMailKeyList(list, lookup.accountAuthorityPublicKey, previous)
    previous = list
  }
  if (!newest || newest.address !== lookup.address || newest.account !== lookup.account) {
    throw new UnverifiedKeys(address)
  }
  const kept: { publicKey: string; primary: boolean; flags: number }[] = []
  for (const row of lookup.keys) {
    const info = await inspectMailAddressPublicKey(row.publicKey, lookup.address)
    const listed = newest.keys.find((k) => k.fingerprint === info.fingerprint && k.sha256Fingerprint === info.sha256Fingerprint)
    if (listed) kept.push({ publicKey: row.publicKey, primary: listed.primary, flags: listed.flags })
  }
  const primary = kept.find((k) => k.primary)
  if (!primary) throw new UnverifiedKeys(address)
  return {
    address: lookup.address,
    account: lookup.account,
    authorityPublicKey: lookup.accountAuthorityPublicKey,
    primary: primary.publicKey,
    // A key its owner marked compromised no longer vouches for anything.
    all: [primary, ...kept.filter((k) => k !== primary)].filter((k) => k.flags & MAIL_KEY_FLAGS.notCompromised).map((k) => k.publicKey),
  }
}

/** A Kutup address's checked keys, looked up once per page. */
export function addressKeys(address: string): Promise<AddressKeys> {
  const key = address.toLowerCase()
  let pending = cache.get(key)
  if (!pending) {
    pending = load(key)
    pending.catch(() => cache.delete(key))
    cache.set(key, pending)
  }
  return pending
}

// --- Outside addresses (docs/plans/mail.md, C3) ------------------------------

/** An outside address's OpenPGP key, found by the server and checked here too. */
export interface OutsideKey {
  address: string
  source: 'wkd' | 'proton' | 'keysOpenpgp'
  /** Binary, base64. */
  publicKey: string
  fingerprint: string
}

const outsideCache = new Map<string, Promise<OutsideKey | null>>()

async function loadOutside(address: string): Promise<OutsideKey | null> {
  let found: { address: string; source: OutsideKey['source']; publicKey: string }
  try {
    found = (await api.get<typeof found>('/mail/keys/outside', { params: { email: address } })).data
  } catch (error) {
    if ((error as { response?: { status?: number } }).response?.status === 404) return null
    throw error
  }
  // The same checks the server made, so a key is never used on its word alone.
  const info = await inspectExternalMailKey(fromBase64(found.publicKey), address)
  return { address, source: found.source, publicKey: info.publicKey, fingerprint: info.fingerprint }
}

/**
 * An outside address's key from its Web Key Directory, Proton or
 * keys.openpgp.org, or `null` when none of them has a usable one. Looked
 * up once per page; a failed lookup is tried again next time.
 */
export function outsideKey(address: string): Promise<OutsideKey | null> {
  const key = address.toLowerCase()
  let pending = outsideCache.get(key)
  if (!pending) {
    pending = loadOutside(key)
    pending.catch(() => outsideCache.delete(key))
    outsideCache.set(key, pending)
  }
  return pending
}
