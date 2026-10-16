import { foldAddress, fromBase64, inspectExternalMailKey, inspectMailAddressPublicKey, MAIL_KEY_FLAGS, verifyMailGroupKeyChain, verifyMailKeyList, type SignedMailKeyList } from '@kutup/crypto'
import { driveIdentityOf } from '@kutup/drive-core/identity'
import { pinnedVerdict } from '@kutup/drive-core/identityPins'
import { OlderThanSeenError, revisionGuard } from '@kutup/crypto/revisionGuard'
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

/** A person's address: lists signed by their account authority. */
interface PersonKeyLookup {
  address: string
  /** The account the address belongs to (server-asserted). */
  server: string
  accountId: string
  accountAuthorityPublicKey: string
  keys: PublicKeyRow[]
  keyLists: { data: string; signature: string }[]
}

/** A shared mailbox: lists signed by its own group signer (docs/plans/mail-groups.md). */
interface GroupKeyLookup {
  address: string
  server: string
  groupId: string
  /** Base64: the chain's first signer, bound by the lists' key id. */
  firstSigner: string
  keys: PublicKeyRow[]
  keyLists: { data: string; signature: string }[]
  /** Base64 handovers to each next signer; absent when none. */
  signerHandovers?: string[]
}

type KeyLookup = PersonKeyLookup | GroupKeyLookup

function isGroupLookup(lookup: KeyLookup): lookup is GroupKeyLookup {
  return 'groupId' in lookup
}

/** A shared mailbox's verified chain, as the pin list checks it. */
export interface GroupChainOf {
  server: string
  groupId: string
  signers: string[]
  digests: string[]
}

export interface AddressKeys {
  address: string
  /** The newest key list's sequence, held to what this device has seen. */
  sequence: number
  /** A shared mailbox: its verified chain, held to the pin list by its id. */
  group?: GroupChainOf
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
  // A shared mailbox is no person and has no address pin: its chain is
  // verified on every lookup and guarded against rollback; group pins by
  // (server, group id) come with the pin list's groups section
  // (docs/plans/account-ids.md, slice 3).
  if (keys.group) return keys
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
  return pinned(await notRolledBack(address, await verified(address, lookup)))
}

/** What the revision guard calls an address's key list. */
export const KEY_LIST_GUARD_SCOPE = 'mail-key-list'

/**
 * Refuses a key list older than this device has seen for the same address
 * under the same signer (a person's account authority, or a shared
 * mailbox's chain from its first signer, across handovers): a server cannot
 * hand back an earlier
 * list, for instance one listing a key someone who left still holds. Another
 * signer (a reset, a freed name now someone else's) starts its own count;
 * the pin check after this says whether that signer is the one known.
 */
async function notRolledBack(address: string, keys: AddressKeys): Promise<AddressKeys> {
  const session = getSession()
  if (!session) return keys
  const folded = (await foldAddress(keys.address)) ?? keys.address
  // A person's list is counted per authority; a shared mailbox's per mailbox
  // and chain (its first signer: a handover stays in one chain, while an
  // administrator's new chain starts its own count, and the pin check after
  // this says it changed).
  const id = keys.group ? `${folded}:group:${keys.group.groupId}:${keys.group.signers[0]}` : `${folded}:${keys.authorityPublicKey}`
  try {
    await revisionGuard(session).accept(KEY_LIST_GUARD_SCOPE, id, keys.sequence)
  } catch (error) {
    if (error instanceof OlderThanSeenError) throw new UnverifiedKeys(address)
    throw error
  }
  return keys
}

/**
 * A lookup's keys, kept only when the account's signed key lists name them.
 * The answer names the address as stored (another spelling of the address
 * asked: one account per folded name), which its newest list names too.
 */
export async function verified(address: string, lookup: KeyLookup): Promise<AddressKeys> {
  const asked = await foldAddress(address)
  if (!asked || asked !== (await foldAddress(lookup.address))) throw new UnverifiedKeys(address)
  // An account lives on the server of its address.
  if (lookup.server !== lookup.address.slice(lookup.address.lastIndexOf('@') + 1).toLowerCase()) throw new UnverifiedKeys(address)
  let newest: SignedMailKeyList | null = null
  let group: GroupChainOf | undefined
  let signer: string
  try {
    if (isGroupLookup(lookup)) {
      const chain = await verifyMailGroupKeyChain(lookup.groupId, lookup.firstSigner, lookup.keyLists, lookup.signerHandovers ?? [])
      newest = chain.newest
      signer = chain.signer
      group = { server: lookup.server, groupId: lookup.groupId, signers: chain.signers, digests: chain.digests }
    } else {
      let previous: { data: string; signature: string } | undefined
      for (const list of lookup.keyLists) {
        newest = await verifyMailKeyList(list, lookup.accountAuthorityPublicKey, previous)
        previous = list
      }
      signer = lookup.accountAuthorityPublicKey
    }
  } catch {
    // A list or chain that does not verify: these keys are not the owner's.
    throw new UnverifiedKeys(address)
  }
  if (!newest || newest.address !== lookup.address) {
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
    sequence: newest.sequence,
    ...(isGroupLookup(lookup) ? { group } : {}),
    authorityPublicKey: signer,
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
