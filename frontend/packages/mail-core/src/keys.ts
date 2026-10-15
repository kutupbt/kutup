import { foldAddress, fromBase64, inspectExternalMailKey, inspectMailAddressPublicKey, MAIL_KEY_FLAGS, verifyMailKeyList, type SignedMailKeyList } from '@kutup/crypto'
import { driveIdentityOf } from '@kutup/drive-core/identity'
import { pinnedVerdict } from '@kutup/drive-core/identityPins'
import api from '@kutup/session/client'
import { getSession } from '@kutup/session/store'

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

/**
 * The keys are signed by another authority than the one the account's pin
 * list holds for this person (docs/plans/username-renames.md): a reset, a
 * name someone else took, or a server handing out keys of its own.
 */
export class KeysIdentityChanged extends UnverifiedKeys {
  constructor(
    address: string,
    /** Where the person met at this address is now, when the list knows (a name taken by someone else). */
    readonly now?: string,
  ) {
    super(address)
    this.message = `the keys of ${address} are not signed by the account met before`
  }
}

/**
 * `keys` held against the pin list shared with Drive and Chat: a pinned
 * person's keys must be signed by the pinned authority, and an address that
 * person left needs their verified rename chain naming both addresses.
 * Someone never met is trusted on first use, as before.
 */
async function pinned(keys: AddressKeys): Promise<AddressKeys> {
  const session = getSession()
  if (!session?.username) return keys
  const verdict = await pinnedVerdict(await driveIdentityOf(session), keys.address, keys.authorityPublicKey)
  if (verdict.kind === 'changed') throw new KeysIdentityChanged(keys.address, verdict.now)
  return keys
}

/** The address is a group's: its members' keys come from `groupMembers`. */
export class GroupAddress extends Error {
  constructor(readonly address: string) {
    super(`${address} is a group`)
  }
}

/** The group does not take mail from this account. */
export class GroupNotAllowed extends Error {
  constructor(readonly address: string) {
    super(`${address} does not take mail from you`)
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
    const response = (error as { response?: { status?: number; data?: { code?: string } } }).response
    if (response?.status === 404 && response.data?.code === 'group') throw new GroupAddress(address)
    if (response?.status === 404) throw new NoKutupAddress(address)
    throw error
  }
  return pinned(await verified(address, lookup))
}

/**
 * A lookup's keys, kept only when the account's signed key lists name them.
 * The answer names the address as stored and the account its newest list
 * names: another spelling of the address asked (one account per folded name),
 * or, for an old address of a renamed account, its name then.
 */
export async function verified(address: string, lookup: KeyLookup): Promise<AddressKeys> {
  const asked = await foldAddress(address)
  if (!asked || asked !== (await foldAddress(lookup.address))) throw new UnverifiedKeys(address)
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
  /** Binary, base64: the newest usable key, the one mail is encrypted to. */
  publicKey: string
  fingerprint: string
  /** Every usable key the source served, newest first, for a contact's key table (docs/plans/contact-keys.md). */
  keys: { publicKey: string; fingerprint: string }[]
}

const outsideCache = new Map<string, Promise<OutsideKey | null>>()

async function loadOutside(address: string): Promise<OutsideKey | null> {
  let found: { address: string; source: OutsideKey['source']; publicKey: string; keys?: { publicKey: string }[] }
  try {
    found = (await api.get<typeof found>('/mail/keys/outside', { params: { email: address } })).data
  } catch (error) {
    if ((error as { response?: { status?: number } }).response?.status === 404) return null
    throw error
  }
  // The same checks the server made, so a key is never used on its word alone.
  const info = await inspectExternalMailKey(fromBase64(found.publicKey), address)
  const others = await Promise.all(
    (found.keys ?? []).map((key) => inspectExternalMailKey(fromBase64(key.publicKey), address).catch(() => null)),
  )
  const keys = [info, ...others.filter((key): key is NonNullable<typeof key> => key !== null && key.fingerprint !== info.fingerprint)]
  return { address, source: found.source, publicKey: info.publicKey, fingerprint: info.fingerprint, keys: keys.map(({ publicKey, fingerprint }) => ({ publicKey, fingerprint })) }
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

/**
 * Who receives a group's mail, each with their checked keys (docs/plans/
 * mail-groups.md): a message to a distribution list is encrypted to every
 * member. Asked fresh each time, as membership changes.
 */
export async function groupMembers(address: string): Promise<AddressKeys[]> {
  let members: KeyLookup[]
  try {
    members = (await api.get<{ members: KeyLookup[] }>('/mail/groups/recipients', { params: { email: address } })).data.members
  } catch (error) {
    const response = (error as { response?: { status?: number } }).response
    if (response?.status === 403) throw new GroupNotAllowed(address)
    if (response?.status === 404) throw new NoKutupAddress(address)
    throw error
  }
  return Promise.all(members.map(async (member) => pinned(await verified(member.address, member))))
}
