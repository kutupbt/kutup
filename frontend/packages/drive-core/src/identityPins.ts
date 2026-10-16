// Who other people are (docs/plans/drive-identity-pins.md).
//
// Drive seals shares to other people's Drive keys and checks shares against
// their signing keys; both reach the browser through the server. Each account
// signs a binding of its Drive keys to its authority, and this account keeps
// a synced, encrypted list of the authority it first met for every account
// (a pin), keyed by the account's permanent id (docs/plans/account-ids.md);
// addresses are only how a person is found. A key the server hands out is
// trusted only as far as:
//
// - a binding by that account's authority covers it, and
// - that authority is the one pinned for the account (pinned on first use).
//
// Like Proton Drive, a failure warns instead of blocking (decided 2026-10-10):
// callers show the status next to the person and ask before sharing to them.

import { isAxiosError } from 'axios'
import { foldAddress, verifyAccountRenameChain, type AccountRenameV1 } from '@kutup/crypto/accountRename'
import { sameAccount, type AccountRef } from '@kutup/crypto/accountRef'
import {
  applyAccountRenameToPins,
  deriveSafetyNumber,
  identityPinsAt,
  incarnationIdOfAuthority,
  lookupGroupPin,
  lookupIdentityPin,
  openIdentityPins,
  EMPTY_PINS,
  pinAddress,
  recordGroupPin,
  recordIdentityPin,
  safetyQrMatches,
  sealIdentityPins,
  verifyDriveKeyBinding,
  type GroupChain,
  type IdentityPin,
  type PinsText,
  type PinUpdate,
  type Recorded,
} from '@kutup/crypto/identityPins'
import { OlderThanSeenError, revisionGuard, toBase64 } from '@kutup/crypto'
import {
  accountHead,
  HeadBlockedError,
  IndexMismatchError,
  NotInVerifiedIndexError,
  type VerifiedIndex,
} from '@kutup/session/accountHead'
import api from '@kutup/session/client'
import type { DriveIdentity } from './identity'

/**
 * What can be said about a person's keys:
 * - `ok`: their authority vouches for them and is the one pinned (`verified`
 *   when compared in person).
 * - `unproven`: their account has not signed a binding yet (it does at its
 *   next sign-in); nothing contradicts the keys, nothing confirms them.
 * - `invalid`: the binding does not cover these keys, or does not verify.
 * - `changed`: a valid binding by another authority than the pinned one (an
 *   administrator's reset, or a server handing out keys of its own). Warned
 *   until the user accepts it.
 * - `someoneElse`: the address belongs to someone the list knows, and the
 *   account found there is not them (a freed name taken, or a server pointing
 *   the name elsewhere): `now` is where that person is, when they moved on.
 * - `renamed`: the address is a name this person left (a verified rename
 *   chain says so, docs/plans/username-renames.md): they are `now` there.
 * - `unknown`: could not be checked (no connection, the lookup failed).
 *
 * `name`: on `ok`, the account's own name when it is not the address asked
 * about; on `someoneElse`, the own name of an account the user already knows
 * found there (nothing to accept: they are someone the user knows, at an
 * address that is not theirs). As in Signal, an address only finds an account;
 * the person is shown by their own name (proved by their signed rename
 * chain, or the address they were first met at), never by what was typed.
 * `formerly` (on `ok`): the address they held before the one asked about.
 */
export type IdentityStatus =
  | { kind: 'ok'; verified: boolean; formerly?: string; name?: string }
  | { kind: 'renamed'; now: string; verified: boolean }
  | { kind: 'unproven' }
  | { kind: 'invalid' }
  | { kind: 'changed' }
  | { kind: 'someoneElse'; now?: string; name?: string }
  | { kind: 'unknown' }

/** The keys a share or a lookup put to this person; what is absent is not compared. */
export interface ClaimedKeys {
  driveHpkePublicKey?: string
  driveSigningPublicKey?: string
  incarnationId?: string
  authorityPublicKey?: string
}

/** A person as their server describes them. */
export interface PublishedIdentity {
  /** The address they were looked up by. */
  account: string
  /** Who they are, for good: their home server and permanent id. */
  server: string
  accountId: string
  accountAuthorityPublicKey: string
  driveHpkePublicKey: string
  driveSigningPublicKey: string
  driveKeyBinding?: string | null
}

/** An account as a single lookup answers it (`/users/by-address`, `/users/by-id`). */
export interface AccountAnswer extends PublishedIdentity {
  username: string
  accountIncarnationId: string
}

// ------------------------------------------------------------ lookups

const published = new Map<string, Promise<PublishedIdentity>>()

/** A person's published identity: here, or through their server. Cached for the page. */
export function publishedIdentity(me: DriveIdentity, account: string): Promise<PublishedIdentity> {
  let pending = published.get(account)
  if (!pending) {
    pending = fetchIdentity(me, account)
    published.set(account, pending)
    pending.catch(() => published.delete(account))
  }
  return pending
}

async function fetchIdentity(me: DriveIdentity, account: string): Promise<PublishedIdentity> {
  const [username, server] = account.split('@')
  if (!username || !server) throw new Error('not an account address')
  const data =
    server === me.account.split('@')[1]
      ? await localIdentity(account)
      // Another server's account: the same lookup, through this server.
      : (await api.get<PublishedIdentity>(`/users/by-address/${encodeURIComponent(account)}`)).data
  if (data.account !== account) throw new Error('the lookup answered for another account')
  // An account lives on the server of its address.
  if (data.server !== server) throw new Error('the lookup answered for an account on another server')
  return data
}

/** The account a lookup answered for. */
function refOf(person: PublishedIdentity): AccountRef {
  return { server: person.server, accountId: person.accountId }
}

// People on this server are looked up together: everyone a page asks about
// in the same moment goes in one request (`POST /users/drive-identities`,
// up to 100), not one lookup each against the per-address lookup limit.
const BATCH = 100
let queued: { account: string; resolve: (identity: PublishedIdentity) => void; reject: (error: unknown) => void }[] = []
let flushing: ReturnType<typeof setTimeout> | null = null

export class IdentityNotFound extends Error {
  constructor(readonly account: string) {
    super(`no Drive identity for ${account}`)
  }
}

function localIdentity(account: string): Promise<PublishedIdentity> {
  return new Promise((resolve, reject) => {
    queued.push({ account, resolve, reject })
    flushing ??= setTimeout(() => void flush(), 10)
  })
}

async function flush(): Promise<void> {
  const batch = queued
  queued = []
  flushing = null
  for (let start = 0; start < batch.length; start += BATCH) {
    const part = batch.slice(start, start + BATCH)
    try {
      const { data } = await api.post<PublishedIdentity[]>('/users/drive-identities', {
        accounts: [...new Set(part.map((entry) => entry.account))],
      })
      const found = new Map(data.map((identity) => [identity.account, identity]))
      for (const entry of part) {
        const identity = found.get(entry.account)
        if (identity) entry.resolve(identity)
        else entry.reject(new IdentityNotFound(entry.account))
      }
    } catch (error) {
      for (const entry of part) entry.reject(error)
    }
  }
}

// --------------------------------------------------------------- pins

interface PinStore {
  revision: number
  /** The whole list as Rust wrote it: what this app does not know (detached pins, later fields) goes back as it is. */
  pins: PinsText
}

let store: { userId: string; loaded: Promise<PinStore> } | null = null
let writes: Promise<unknown> = Promise.resolve()

/** The highest revision this browser has seen: a server cannot quietly hand back an older list. */
const PINS_SCOPE = 'identity-pins'
const PINS_ID = 'list'

export class PinsRolledBack extends Error {
  constructor() {
    super('the server returned an older identity pin list than this browser has seen')
  }
}

/** The pin list is one value of the account head's `pins` scope (docs/plans/rollback-protection.md). */
const HEAD_SCOPE = 'pins'
const HEAD_ID = 'pins'

function headFor(me: DriveIdentity) {
  return accountHead({ userId: me.userId, masterKey: me.masterKey, envelopeBinding: me.binding })
}

/**
 * The account head's index of the pin list, or null when it cannot vouch
 * (this app is blocked on another history: reads go on, held to this
 * browser's own guard only, and the shell's banner says why).
 */
async function pinsIndex(me: DriveIdentity): Promise<VerifiedIndex | null> {
  try {
    return await (await headFor(me)).verifiedIndex(HEAD_SCOPE)
  } catch (error) {
    if (error instanceof HeadBlockedError) return null
    if (error instanceof IndexMismatchError) throw new PinsRolledBack()
    throw error
  }
}

async function readPins(): Promise<{ revision: number; envelope: string } | null> {
  try {
    return (await api.get<{ revision: number; envelope: string }>('/user/identity-pins')).data
  } catch (error) {
    if (!(isAxiosError(error) && error.response?.status === 404)) throw error
    return null
  }
}

async function fetchPins(me: DriveIdentity): Promise<PinStore> {
  // The list and the head's index are two reads: a write landing between
  // them is read again once before it counts as a list the head does not
  // vouch for.
  for (let attempt = 0; ; attempt++) {
    const index = await pinsIndex(me)
    const data = await readPins()
    try {
      return await openPins(me, data, index)
    } catch (error) {
      if (error instanceof NotInVerifiedIndexError && attempt === 0) continue
      if (error instanceof NotInVerifiedIndexError) throw new PinsRolledBack()
      throw error
    }
  }
}

async function openPins(
  me: DriveIdentity,
  data: { revision: number; envelope: string } | null,
  index: VerifiedIndex | null,
): Promise<PinStore> {
  const guard = revisionGuard(me)
  if (!data) {
    // None stored, though this browser has seen one, or the head lists one:
    // held back by the server.
    if ((await guard.seen(PINS_SCOPE, PINS_ID)) > 0) throw new PinsRolledBack()
    index?.expectListing([])
    return { revision: 0, pins: EMPTY_PINS }
  }
  // The revision is the one sealed in the list's header, not the server's word.
  const { pins, revision } = await openIdentityPins(toBase64(me.masterKey), me.binding, data.envelope)
  index?.expect(HEAD_ID, revision)
  try {
    await guard.accept(PINS_SCOPE, PINS_ID, revision)
  } catch (error) {
    if (error instanceof OlderThanSeenError) throw new PinsRolledBack()
    throw error
  }
  return { revision, pins }
}

function pinStore(me: DriveIdentity): Promise<PinStore> {
  if (!store || store.userId !== me.userId) {
    const loaded = fetchPins(me)
    store = { userId: me.userId, loaded }
    loaded.catch(() => {
      if (store?.loaded === loaded) store = null
    })
  }
  return store.loaded
}

/**
 * Applies `change` to the list and stores it on top of the revision it read
 * (a newer one in its header); when another app stored one first, starts
 * again from that one. One write at a
 * time from this page.
 */
function updatePins(me: DriveIdentity, change: (pins: PinsText) => Promise<PinsText | null>): Promise<void> {
  const run = async () => {
    const head = await headFor(me)
    await head.listedWrite(HEAD_SCOPE, async (_index, attempt) => {
      // Past the first try another app wrote first: read the list again.
      if (attempt > 1) store = null
      const current = await pinStore(me)
      const list = await change(current.pins)
      if (!list) return null
      const guard = revisionGuard(me)
      const revision = await guard.next(PINS_SCOPE, PINS_ID, current.revision)
      const envelope = await sealIdentityPins(toBase64(me.masterKey), me.binding, revision, list)
      return {
        changes: [[HEAD_ID, revision]],
        send: async (sealedHead) => {
          try {
            await api.put('/user/identity-pins', { baseRevision: current.revision, envelope, head: sealedHead })
          } catch (error) {
            // Read again on the next try, whatever the conflict was.
            if (isAxiosError(error) && error.response?.status === 409) store = null
            throw error
          }
          await guard.accept(PINS_SCOPE, PINS_ID, revision)
          store = { userId: me.userId, loaded: Promise.resolve({ revision, pins: list }) }
        },
      }
    })
  }
  const result = writes.then(run, run)
  writes = result.catch(() => undefined)
  return result
}

function now(): string {
  return new Date().toISOString()
}

/**
 * Records `update` about `person` (met at the address they were looked up
 * by) by the rules every app shares (Rust `identity_pins::record`) and
 * stores the list if it changed; what was decided, from the last attempt.
 */
async function recordPin(me: DriveIdentity, person: PublishedIdentity, update: PinUpdate): Promise<Recorded> {
  let outcome: Recorded = { kind: 'unchanged' }
  await updatePins(me, async (pins) => {
    const result = await recordIdentityPin(pins, refOf(person), person.account, person.accountAuthorityPublicKey, update, now())
    outcome = result.result
    return result.changed ? result.pins : null
  })
  return outcome
}

// ------------------------------------------------------------- renames

/** One account's rename chain, as `GET /api/users/renames/:address` and `409 renamed` give it. */
export interface RenameChainEntry {
  incarnationId: string
  authorityPublicKey: string
  current: string
  state: 'current' | 'held' | 'gone'
  chain: AccountRenameV1[]
}

/** Every chain naming an address, newest first; `unavailable`: its server could not say. */
export interface RenameChains {
  version: number
  chains: RenameChainEntry[]
  unavailable?: boolean
}

/** The chains a `409 renamed` carries (a lookup of a name its account left), or null for another error. */
export function renamesOf(error: unknown): RenameChains | null {
  if (!isAxiosError(error) || error.response?.status !== 409) return null
  const data = error.response.data as { code?: string; renames?: RenameChains } | undefined
  return data?.code === 'renamed' && data.renames && Array.isArray(data.renames.chains) ? data.renames : null
}

/** The rename chains that name `address`. */
async function fetchRenames(address: string): Promise<RenameChains> {
  return (await api.get<RenameChains>(`/users/renames/${encodeURIComponent(address)}`)).data
}

/** Where a person known at an address they left is now. */
export interface FollowedRename {
  now: string
  formerly: string
  verified: boolean
}

/**
 * Follows `renames` for `address`: the chain of a person the list met there,
 * signed by their pinned authority (the chain's addresses become their pin's
 * labels; trust is untouched), or, for someone never met, the newest chain
 * whose account goes by another name now (trusted on first use, nothing
 * pinned). Null when nothing can be followed: an unknown format (`version`),
 * a server that could not say, no chain by a pinned authority, an account
 * that is gone.
 */
export async function followRename(me: DriveIdentity, address: string, renames: RenameChains): Promise<FollowedRename | null> {
  if (renames.version !== 1 || renames.unavailable) return null
  const pins = await pinStore(me)
  const known = await identityPinsAt(pins.pins, address)
  for (const pin of known) {
    const entry = renames.chains.find((chain) => chain.authorityPublicKey === pin.authorityPublicKey && chain.state === 'current')
    if (!entry) continue
    let moved: string | null = null
    try {
      await updatePins(me, async (list) => {
        const applied = await applyAccountRenameToPins(list, pin.account, entry.chain, now())
        moved = applied.applied.to
        return applied.applied.changed ? applied.pins : null
      })
    } catch {
      return null
    }
    const current = moved as string | null
    return current ? { now: current, formerly: address, verified: pin.state === 'verified' } : null
  }
  // Someone the list knows was here, and no chain of theirs says where they
  // went: another account's chain is not followed in their place.
  if (known.length > 0) return null
  const asked = await foldAddress(address)
  for (const entry of renames.chains) {
    if (entry.state !== 'current') continue
    try {
      const view = await verifyAccountRenameChain(entry.authorityPublicKey, entry.chain)
      const folded = await Promise.all(view.addresses.map((a) => foldAddress(a)))
      if (asked !== null && folded.includes(asked) && (await foldAddress(view.current)) !== asked) {
        return { now: view.current, formerly: address, verified: false }
      }
    } catch {
      // Not a chain to follow.
    }
  }
  return null
}

/**
 * Whether `authority` may speak for `account`, found at `address`, as far as
 * the pin list knows (Mail's key checks):
 * - `pinned`: the account is pinned to this authority (`name`: its own
 *   name, when it is not `address`);
 * - `changed`: the account is pinned to another authority (a reset, or a
 *   server handing out keys of its own);
 * - `someoneElse`: a person the list knows holds this address, and the
 *   account found there is not them (`now`: where that person is, when they
 *   moved on);
 * - `unknown`: nobody the list knows (trusted on first use).
 */
export type PinnedVerdict =
  | { kind: 'pinned'; name?: string }
  | { kind: 'changed' }
  | { kind: 'someoneElse'; now?: string }
  | { kind: 'unknown' }

export async function pinnedVerdict(me: DriveIdentity, account: AccountRef, address: string, authority: string): Promise<PinnedVerdict> {
  const pins = await pinStore(me)
  const match = await lookupIdentityPin(pins.pins, account, address, authority)
  const holder = (pin: IdentityPin | undefined): PinnedVerdict => {
    const now = pin ? pinAddress(pin) : undefined
    return now && now !== address ? { kind: 'someoneElse', now } : { kind: 'someoneElse' }
  }
  switch (match.kind) {
    case 'pinned': {
      if (match.others.length > 0) return holder(match.others[0])
      if (match.authority !== 'same') return { kind: 'changed' }
      const name = match.knownAt ? undefined : pinAddress(match.pin)
      return name ? { kind: 'pinned', name } : { kind: 'pinned' }
    }
    case 'someoneElse':
      return holder(match.pins[0])
    case 'new':
      return { kind: 'unknown' }
  }
}

/**
 * Where the account at `address` is now, by its verified rename chain
 * (`authority` signs it), or `address` itself: an old address's links (Chat,
 * calls) go to the account's current name.
 */
export async function currentAddressOf(address: string, authority: string): Promise<string> {
  const renames = await fetchRenames(address).catch(() => null)
  if (!renames || renames.version !== 1 || renames.unavailable) return address
  const asked = await foldAddress(address)
  for (const entry of renames.chains) {
    if (entry.authorityPublicKey !== authority || entry.state !== 'current') continue
    try {
      const view = await verifyAccountRenameChain(authority, entry.chain)
      const folded = await Promise.all(view.addresses.map((a) => foldAddress(a)))
      if (asked !== null && folded.includes(asked)) return view.current
    } catch {
      // Not this account's chain.
    }
  }
  return address
}

/** Two addresses of one account: equal once folded. */
async function sameAddress(a: string, b: string): Promise<boolean> {
  const [x, y] = await Promise.all([foldAddress(a), foldAddress(b)])
  return x !== null && x === y
}

/** The address a pin held before `address` (compared folded), if it has had another. */
async function formerOf(pin: IdentityPin, address: string): Promise<string | undefined> {
  const labels = pin.addresses ?? []
  const asked = await foldAddress(address)
  const folded = await Promise.all(labels.map((label) => foldAddress(label.address)))
  const at = asked === null ? -1 : folded.indexOf(asked)
  return at > 0 ? labels[at - 1].address : undefined
}

// -------------------------------------------------------------- checks

/**
 * How far `account`'s `claimed` keys can be trusted; pins the account's
 * authority the first time it is met with a valid binding.
 */
export async function checkIdentity(me: DriveIdentity, account: string, claimed: ClaimedKeys = {}): Promise<IdentityStatus> {
  if (await sameAddress(account, me.account)) return { kind: 'ok', verified: true }
  let person: PublishedIdentity
  try {
    person = await publishedIdentity(me, account)
  } catch (error) {
    return (await renamedStatus(me, account, error)) ?? { kind: 'unknown' }
  }
  return checkPublished(me, account, person, claimed)
}

/**
 * `checkIdentity` for one lookup answer already in hand: `person` is what the
 * server said `address` (as typed) leads to. The pins are asked about the
 * typed address, so an address a known person holds that leads to anyone
 * else is `someoneElse`, whatever label the answer carries.
 */
async function checkPublished(
  me: DriveIdentity,
  account: string,
  person: PublishedIdentity,
  claimed: ClaimedKeys = {},
): Promise<IdentityStatus> {
  if (sameAccount(refOf(person), me.accountRef)) return { kind: 'ok', verified: true }
  // An account lives on the server of its address.
  if (person.server !== account.slice(account.lastIndexOf('@') + 1).toLowerCase()) return { kind: 'invalid' }
  // The keys in use must be the ones the person's server publishes...
  if (
    (claimed.driveHpkePublicKey && claimed.driveHpkePublicKey !== person.driveHpkePublicKey) ||
    (claimed.driveSigningPublicKey && claimed.driveSigningPublicKey !== person.driveSigningPublicKey) ||
    (claimed.authorityPublicKey && claimed.authorityPublicKey !== person.accountAuthorityPublicKey)
  ) {
    return { kind: 'invalid' }
  }
  const incarnation = await incarnationIdOfAuthority(person.accountAuthorityPublicKey).catch(() => null)
  if (!incarnation || (claimed.incarnationId && claimed.incarnationId !== incarnation)) return { kind: 'invalid' }
  let pins: PinStore
  try {
    pins = await pinStore(me)
  } catch {
    return { kind: 'unknown' }
  }
  const match = await lookupIdentityPin(pins.pins, refOf(person), account, person.accountAuthorityPublicKey)
  const pin = match.kind === 'pinned' ? match.pin : null
  // ...and those its authority vouches for. A binding is never withdrawn: a
  // pinned account without one is a server leaving it out.
  if (!person.driveKeyBinding) return pin ? { kind: 'invalid' } : { kind: 'unproven' }
  const bound = await verifyDriveKeyBinding(
    refOf(person),
    person.accountAuthorityPublicKey,
    person.driveHpkePublicKey,
    person.driveSigningPublicKey,
    person.driveKeyBinding,
  ).catch(() => false)
  if (!bound) return { kind: 'invalid' }
  if (match.kind === 'pinned') {
    // Someone the list knows holds this address: the account found there is
    // not them, whatever its keys; it is shown by its own name. First, so a
    // key change through someone else's address is never offered to accept.
    if (match.others.length > 0) return someoneElse(match.others[0], account, pinAddress(match.pin))
    if (match.authority !== 'same') return { kind: 'changed' }
    if (match.knownAt) return okStatus(match.pin, account)
    // Found at an address the list does not know for them: their own signed
    // rename chain may prove it (a rename); nothing else does.
    const proven = await proveAddress(me, match.pin, account)
    return proven ? okStatus(proven, account) : okStatus(match.pin, account, pinAddress(match.pin))
  }
  // First met: trusted from now on, at the address they were met at, unless
  // the list knew someone else there (then only when the user accepts).
  // Pinned at the address it was met at: the one typed, not the answer's label.
  const recorded = await recordPin(me, { ...person, account }, 'firstSeen').catch((): Recorded => ({ kind: 'unchanged' }))
  // Another account's authority handed out for this one.
  if (recorded.kind === 'authorityElsewhere') return { kind: 'invalid' }
  if (recorded.kind === 'addressHadOthers') return someoneElse(recorded.pins[0], account)
  if (match.kind === 'someoneElse') return someoneElse(match.pins[0], account)
  return { kind: 'ok', verified: false }
}

/**
 * `address`, proved to be `pin`'s by its own rename chain (signed by the
 * pinned authority, naming `address` as where the account is now): the chain
 * is followed into the list, and the pin returned as it is now. Null when
 * there is no such chain: the address stays a handle that found them.
 */
async function proveAddress(me: DriveIdentity, pin: IdentityPin, address: string): Promise<IdentityPin | null> {
  const renames = await fetchRenames(address).catch(() => null)
  if (!renames || renames.version !== 1 || renames.unavailable) return null
  const entry = renames.chains.find((chain) => chain.authorityPublicKey === pin.authorityPublicKey && chain.state === 'current')
  if (!entry || !(await sameAddress(entry.current, address))) return null
  let proven: IdentityPin | null = null
  try {
    await updatePins(me, async (list) => {
      const applied = await applyAccountRenameToPins(list, pin.account, entry.chain, now())
      proven = applied.pins.list.pins.find((known) => sameAccount(known.account, pin.account)) ?? null
      return applied.applied.changed ? applied.pins : null
    })
  } catch {
    return null
  }
  return proven
}

function someoneElse(holder: IdentityPin | undefined, address: string, name?: string): IdentityStatus {
  const now = holder ? pinAddress(holder) : undefined
  return { kind: 'someoneElse', ...(now && now !== address ? { now } : {}), ...(name ? { name } : {}) }
}

async function okStatus(pin: IdentityPin, address: string, name?: string): Promise<IdentityStatus> {
  const formerly = await formerOf(pin, address)
  return { kind: 'ok', verified: pin.state === 'verified', ...(formerly ? { formerly } : {}), ...(name ? { name } : {}) }
}

/**
 * When a lookup of `account` failed: whether it is a name its person left.
 * Their server says so (`409 renamed`, with the chains); one of this server's
 * names that is not found is asked about only when it is pinned.
 */
async function renamedStatus(me: DriveIdentity, account: string, error: unknown): Promise<IdentityStatus | null> {
  try {
    let renames = renamesOf(error)
    if (!renames && error instanceof IdentityNotFound) {
      const pins = await pinStore(me)
      if ((await identityPinsAt(pins.pins, account)).length === 0) return null
      renames = await fetchRenames(account)
    }
    if (!renames) return null
    const followed = await followRename(me, account, renames)
    return followed ? { kind: 'renamed', now: followed.now, verified: followed.verified } : null
  } catch {
    return null
  }
}

/**
 * The name the list knows `account` by: the address it holds now as its own
 * signed rename chain proves (or the one it was first met at). Null when the
 * list does not know it.
 */
export async function pinnedNameOf(me: DriveIdentity, account: AccountRef): Promise<string | null> {
  const pin = (await pinStore(me)).pins.list.pins.find((known) => sameAccount(known.account, account))
  return (pin && pinAddress(pin)) ?? null
}

/**
 * Whether `account` is in the list (met before in Drive, Chat or the CLI).
 * Tells a Kutup account on another server from an ordinary email address
 * without asking that server: only a listed one is worth looking up.
 */
export async function isPinned(me: DriveIdentity, account: string): Promise<boolean> {
  return (await identityPinsAt((await pinStore(me)).pins, account)).length > 0
}

/**
 * Sharing to an address its person left: they are `now` there (a verified
 * rename chain says so). Share with them there instead.
 */
export class RecipientRenamed extends Error {
  constructor(
    readonly account: string,
    readonly now: string,
  ) {
    super(`${account} is now ${now}`)
  }
}

/**
 * For a recipient lookup that failed: `RecipientRenamed` when the address
 * is a name its person left and their chain can be followed; the error
 * itself otherwise.
 */
export async function recipientError(me: DriveIdentity, account: string, error: unknown): Promise<unknown> {
  const renames = renamesOf(error)
  if (!renames) return error
  const followed = await followRename(me, account, renames).catch(() => null)
  return followed ? new RecipientRenamed(account, followed.now) : error
}

/** Sharing to someone whose identity is in doubt, before the user said to go on. */
export class IdentityNotConfirmed extends Error {
  constructor(
    readonly account: string,
    readonly status: Extract<IdentityStatus, { kind: 'changed' | 'invalid' | 'someoneElse' }>,
  ) {
    super(`the identity of ${account} could not be confirmed (${status.kind})`)
  }
}

/**
 * Before sealing anything to `person`, the account a lookup of `address`
 * (as the user typed it) answered: checked as `checkIdentity` checks, against
 * the pins by the typed address. Seal to exactly `person` afterwards, never
 * to a second answer. A changed or invalid identity, or someone else at a
 * known person's address, stops the share with `IdentityNotConfirmed` until
 * the user confirms (`confirmed`): Drive warns, it does not refuse.
 */
export async function confirmRecipient(
  me: DriveIdentity,
  address: string,
  person: AccountAnswer,
  confirmed = false,
): Promise<IdentityStatus> {
  const status = await checkAnswer(me, address, person)
  if ((status.kind === 'changed' || status.kind === 'invalid' || status.kind === 'someoneElse') && !confirmed) {
    throw new IdentityNotConfirmed(address, status)
  }
  return status
}

/**
 * How far one lookup answer for `address` (as typed) can be trusted, checked
 * against the pins by that address (`checkIdentity`'s verdicts). Whatever is
 * then done is done to exactly this answer.
 */
export function checkAnswer(me: DriveIdentity, address: string, answer: AccountAnswer): Promise<IdentityStatus> {
  // The incarnation is the one its authority names.
  return checkPublished(me, address, answer, { incarnationId: answer.accountIncarnationId })
}

/**
 * The account `address` leads to, here or on another server: one lookup
 * (`/users/by-address`). Not found is `RecipientNotFound`-worthy (null); a
 * name its person left is `RecipientRenamed`.
 */
export async function lookupAddress(me: DriveIdentity, address: string): Promise<AccountAnswer | null> {
  try {
    return (await api.get<AccountAnswer>(`/users/by-address/${encodeURIComponent(address)}`)).data
  } catch (error) {
    if ((error as { response?: { status?: number } }).response?.status === 404) return null
    throw await recipientError(me, address, error)
  }
}

/**
 * Trust `account`'s current authority from now on: after a change the user
 * knows about (their account was wiped and set up again). The old identity is
 * kept in the pin's history.
 */
export async function acceptIdentity(me: DriveIdentity, account: string): Promise<void> {
  const person = await publishedIdentity(me, account)
  if (!person.driveKeyBinding) throw new Error('this account has not signed its keys yet')
  const bound = await verifyDriveKeyBinding(
    refOf(person),
    person.accountAuthorityPublicKey,
    person.driveHpkePublicKey,
    person.driveSigningPublicKey,
    person.driveKeyBinding,
  )
  if (!bound) throw new Error('the keys are not signed by this account')
  const recorded = await recordPin(me, person, 'accepted')
  // Another account's authority handed out for this one: never accepted.
  if (recorded.kind === 'authorityElsewhere') throw new Error('these keys belong to another account')
  // Reached by someone else's address: a key change is accepted only for the
  // person opened by their own name.
  if (recorded.kind === 'addressHeldByOthers') throw new Error('this address belongs to someone else')
}

/** A person's published identity, once their binding is checked; throws otherwise. */
async function boundIdentity(me: DriveIdentity, account: string): Promise<PublishedIdentity> {
  const person = await publishedIdentity(me, account)
  const bound =
    Boolean(person.driveKeyBinding) &&
    (await verifyDriveKeyBinding(
      refOf(person),
      person.accountAuthorityPublicKey,
      person.driveHpkePublicKey,
      person.driveSigningPublicKey,
      person.driveKeyBinding!,
    ).catch(() => false))
  if (!bound) throw new IdentityUnproven(account)
  return person
}

/** Someone whose keys their account has not (validly) signed: nothing to compare. */
export class IdentityUnproven extends Error {
  constructor(readonly account: string) {
    super(`${account} has no valid Drive key binding`)
  }
}

/**
 * The safety number this account and `account` compare in person (the same
 * one Chat shows), for their current identity.
 */
export async function personSafetyNumber(me: DriveIdentity, account: string): Promise<{ fingerprint: string; qrPayload: string }> {
  const person = await boundIdentity(me, account)
  return deriveSafetyNumber(me.accountRef, me.authorityPublicKey, refOf(person), person.accountAuthorityPublicKey)
}

/** The scanned safety QR did not come from `account`'s current identity. */
export class SafetyNumberMismatch extends Error {
  constructor() {
    super('the scanned safety number is not this pair of accounts')
  }
}

/**
 * Mark `account` verified: the user scanned their safety QR (or pasted it)
 * and it is exactly the expected one for both accounts. A changed identity
 * verified in person is accepted with it. Every app of the account sees it.
 */
export async function verifyPerson(me: DriveIdentity, account: string, scanned: string): Promise<void> {
  const person = await boundIdentity(me, account)
  const matches = await safetyQrMatches(me.accountRef, me.authorityPublicKey, refOf(person), person.accountAuthorityPublicKey, scanned)
  if (!matches) throw new SafetyNumberMismatch()
  const recorded = await recordPin(me, person, 'verified')
  if (recorded.kind === 'authorityElsewhere' || recorded.kind === 'addressHeldByOthers') throw new SafetyNumberMismatch()
}

// ------------------------------------------------------ shared mailboxes

/**
 * Whether a shared mailbox's verified key-list chain (docs/plans/mail-groups.md)
 * is the one the list knows (Mail's key checks): `pinned` (it continues the
 * pinned signer and list; the pin moves forward), `new` (trusted on first
 * use; pinned now), or `changed` (another signer, a restarted chain, a
 * rollback, a fork): warned about until the user accepts it.
 */
export type GroupVerdict = { kind: 'pinned' } | { kind: 'new' } | { kind: 'changed' }

export async function checkGroup(me: DriveIdentity, server: string, groupId: string, chain: GroupChain): Promise<GroupVerdict> {
  const match = await lookupGroupPin((await pinStore(me)).pins, server, groupId, chain)
  if (match.kind === 'changed') return { kind: 'changed' }
  // Pinned on first use, or moved forward along its own line; a failure to
  // store it leaves the check as it is.
  await updatePins(me, async (list) => {
    const result = await recordGroupPin(list, server, groupId, chain, 'firstSeen', now())
    return result.changed ? result.pins : null
  }).catch(() => undefined)
  return match.kind === 'same' ? { kind: 'pinned' } : { kind: 'new' }
}

/** Whether the list knows the shared mailbox `groupId` on `server`. */
export async function isGroupPinned(me: DriveIdentity, server: string, groupId: string): Promise<boolean> {
  return ((await pinStore(me)).pins.list.groups ?? []).some((pin) => pin.server === server && pin.groupId === groupId)
}

/** Trust a shared mailbox's chain as published now, in place of the pinned one (the user knows why it changed). */
export async function acceptGroup(me: DriveIdentity, server: string, groupId: string, chain: GroupChain): Promise<void> {
  await updatePins(me, async (list) => {
    const result = await recordGroupPin(list, server, groupId, chain, 'accepted', now())
    return result.changed ? result.pins : null
  })
}

/** Test seam: forget what this page has looked up and pinned. */
export function resetIdentityPinsForTesting(): void {
  published.clear()
  queued = []
  flushing = null
  store = null
  writes = Promise.resolve()
}
