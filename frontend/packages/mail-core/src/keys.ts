import { inspectMailAddressPublicKey, verifyMailKeyList, type SignedMailKeyList } from '@kutup/crypto'
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
  /** Every key the newest list keeps, primary first, to check signatures. */
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
  const kept: { publicKey: string; primary: boolean }[] = []
  for (const row of lookup.keys) {
    const info = await inspectMailAddressPublicKey(row.publicKey, lookup.address)
    const listed = newest.keys.find((k) => k.fingerprint === info.fingerprint && k.sha256Fingerprint === info.sha256Fingerprint)
    if (listed) kept.push({ publicKey: row.publicKey, primary: listed.primary })
  }
  const primary = kept.find((k) => k.primary)
  if (!primary) throw new UnverifiedKeys(address)
  return {
    address: lookup.address,
    account: lookup.account,
    authorityPublicKey: lookup.accountAuthorityPublicKey,
    primary: primary.publicKey,
    all: [primary.publicKey, ...kept.filter((k) => k !== primary).map((k) => k.publicKey)],
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
