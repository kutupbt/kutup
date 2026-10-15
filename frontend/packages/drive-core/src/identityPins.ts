// Who other people are (docs/plans/drive-identity-pins.md).
//
// Drive seals shares to other people's Drive keys and checks shares against
// their signing keys; both reach the browser through the server. Each account
// signs a binding of its Drive keys to its authority, and this account keeps
// a synced, encrypted list of the authority it first met for every address
// (a pin). A key the server hands out is trusted only as far as:
//
// - a binding by that account's authority covers it, and
// - that authority is the one pinned for the address (pinned on first use).
//
// Like Proton Drive, a failure warns instead of blocking (decided 2026-10-10):
// callers show the status next to the person and ask before sharing to them.

import { isAxiosError } from 'axios'
import { foldAddress, verifyAccountRenameChain, type AccountRenameV1 } from '@kutup/crypto/accountRename'
import {
  applyAccountRenameToPins,
  deriveSafetyNumber,
  incarnationIdOfAuthority,
  lookupIdentityPin,
  openIdentityPins,
  EMPTY_PINS,
  recordIdentityPin,
  safetyQrMatches,
  sealIdentityPins,
  verifyDriveKeyBinding,
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
 * - `changed`: a valid binding by another authority than the pinned one —
 *   a new account under the same address (after an administrator's wipe), or
 *   a server handing out keys of its own. Warned until the user accepts it.
 * - `renamed`: the address is a name this person left (a verified rename
 *   chain says so, docs/plans/username-renames.md): they are `now` there.
 * - `unknown`: could not be checked (no connection, the lookup failed).
 *
 * `formerly` (on `ok`): the address the person was known by before their
 * newest rename, when they have one.
 */
export type IdentityStatus =
  | { kind: 'ok'; verified: boolean; formerly?: string }
  | { kind: 'renamed'; now: string; verified: boolean }
  | { kind: 'unproven' }
  | { kind: 'invalid' }
  | { kind: 'changed' }
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
  account: string
  accountAuthorityPublicKey: string
  driveHpkePublicKey: string
  driveSigningPublicKey: string
  driveKeyBinding?: string | null
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
      : (await api.get<PublishedIdentity>(`/drive/federation/users/${encodeURIComponent(username)}`, { params: { server } })).data
  if (data.account !== account) throw new Error('the lookup answered for another account')
  return data
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
 * Records `update` about `account` by the rules every app shares (Rust
 * `identity_pins::record`) and stores the list if it changed; what was
 * decided, from the last attempt.
 */
async function recordPin(me: DriveIdentity, account: string, authority: string, update: PinUpdate): Promise<Recorded> {
  let outcome: Recorded = { kind: 'unchanged' }
  await updatePins(me, async (pins) => {
    const result = await recordIdentityPin(pins, account, authority, update, now())
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
 * Follows `renames` for `address`: the chain of the authority pinned there
 * (its pin moves to the chain's current address, with its trust and
 * history), or, for someone never met, the newest chain whose account goes
 * by another name now (trusted on first use, nothing pinned). Null when
 * nothing can be followed: an unknown format (`version`), a server that
 * could not say, a pinned authority with no chain or one that does not
 * verify, an account that is gone. A pin is never moved on doubt.
 */
export async function followRename(me: DriveIdentity, address: string, renames: RenameChains): Promise<FollowedRename | null> {
  if (renames.version !== 1 || renames.unavailable) return null
  const pins = await pinStore(me)
  const match = await lookupIdentityPin(pins.pins, address, null)
  const pin = match.kind === 'pinned' || match.kind === 'returned' ? match.pin : null
  if (pin) {
    const entry = renames.chains.find((chain) => chain.authorityPublicKey === pin.authorityPublicKey && chain.state === 'current')
    if (!entry) return null
    let moved: { from: string; to: string } | null = null
    try {
      await updatePins(me, async (list) => {
        const applied = await applyAccountRenameToPins(list, entry.authorityPublicKey, entry.chain)
        moved = applied.applied
        return applied.applied.changed ? applied.pins : null
      })
    } catch {
      return null
    }
    const done = moved as { from: string; to: string } | null
    return done ? { now: done.to, formerly: address, verified: pin.state === 'verified' } : null
  }
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
 * Whether `authority` may speak for `address` as far as the pin list knows
 * (Mail's key checks, docs/plans/username-renames.md):
 * - `pinned`: the address is pinned to this authority;
 * - `renamed`: the authority is pinned under another address of the same
 *   account, and its verified rename chain names both (`now`: where it is);
 * - `changed`: the list holds another authority for the address; or a
 *   person it knows had the address and someone else has it now (`now`:
 *   where that person is, when known); or it names this authority elsewhere
 *   without a chain that covers both; or it is an identity the user replaced;
 * - `unknown`: nobody the list knows (trusted on first use, as before).
 */
export type PinnedVerdict =
  | { kind: 'pinned' }
  | { kind: 'renamed'; now: string }
  | { kind: 'changed'; now?: string }
  | { kind: 'unknown' }

export async function pinnedVerdict(me: DriveIdentity, address: string, authority: string): Promise<PinnedVerdict> {
  const pins = await pinStore(me)
  const match = await lookupIdentityPin(pins.pins, address, authority)
  switch (match.kind) {
    case 'pinned':
      return match.sameAuthority ? { kind: 'pinned' } : { kind: 'changed' }
    case 'returned':
      // A detached pin back at its address: the same person only with its authority.
      return match.pin.authorityPublicKey === authority ? { kind: 'pinned' } : { kind: 'changed' }
    case 'moved': {
      // Someone the list knows had this address and is elsewhere now: whoever
      // holds it is another person (a freed name taken), never trusted silently.
      const now = match.pins.find((moved) => moved.now)?.now ?? undefined
      return now ? { kind: 'changed', now } : { kind: 'changed' }
    }
    case 'replaced':
      return { kind: 'changed' }
    case 'new':
      return { kind: 'unknown' }
    case 'renamed':
      return renamedVerdict(address, authority, match.pin.account)
  }
}

/** An authority pinned under another address: the same account only with a chain naming both. */
async function renamedVerdict(address: string, authority: string, pinnedAt: string): Promise<PinnedVerdict> {
  const renames = await fetchRenames(address).catch(() => null)
  if (!renames || renames.version !== 1 || renames.unavailable) return { kind: 'changed' }
  const [asked, pinned] = await Promise.all([foldAddress(address), foldAddress(pinnedAt)])
  for (const entry of renames.chains) {
    if (entry.authorityPublicKey !== authority) continue
    try {
      const view = await verifyAccountRenameChain(authority, entry.chain)
      const folded = await Promise.all(view.addresses.map((a) => foldAddress(a)))
      if (asked !== null && pinned !== null && folded.includes(asked) && folded.includes(pinned)) {
        return { kind: 'renamed', now: view.current }
      }
    } catch {
      // Not a chain that covers them.
    }
  }
  return { kind: 'changed' }
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

/** The newest address a pin had before its current one. */
function formerOf(pin: IdentityPin): string | undefined {
  return pin.formerly?.at(-1)
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
  // Compared folded, in Rust: any spelling of a pinned address finds its pin.
  const match = await lookupIdentityPin(pins.pins, account, person.accountAuthorityPublicKey)
  const pin = match.kind === 'pinned' ? match.pin : null
  // ...and those its authority vouches for. A binding is never withdrawn: a
  // pinned account without one is a server leaving it out.
  if (!person.driveKeyBinding) return pin ? { kind: 'invalid' } : { kind: 'unproven' }
  const bound = await verifyDriveKeyBinding(
    account,
    person.accountAuthorityPublicKey,
    person.driveHpkePublicKey,
    person.driveSigningPublicKey,
    person.driveKeyBinding,
  ).catch(() => false)
  if (!bound) return { kind: 'invalid' }
  if (pin) {
    if (pin.authorityPublicKey === person.accountAuthorityPublicKey) return okStatus(pin)
    return { kind: 'changed' }
  }
  // Someone known under an earlier name of theirs: follow their chain, which
  // moves the pin here (formerly the address it was at).
  if (match.kind === 'renamed') {
    const followed = await fetchRenames(account)
      .then((renames) => followRename(me, match.pin.account, renames))
      .catch(() => null)
    if (followed && (await sameAddress(followed.now, account))) {
      return { kind: 'ok', verified: followed.verified, formerly: followed.formerly }
    }
  }
  // First met: trusted from now on, unless the list knows better.
  const recorded = await recordPin(me, account, person.accountAuthorityPublicKey, 'firstSeen').catch((): Recorded => ({ kind: 'unchanged' }))
  // Someone the user knew had this address and is elsewhere now: another person.
  if (recorded.kind === 'formerAddressTaken') return { kind: 'changed' }
  // An identity the user replaced (its trust revoked), turning up again.
  if (recorded.kind === 'replacedIdentity') return { kind: 'changed' }
  // The same account, pinned under another of its names.
  if (recorded.kind === 'knownElsewhere') return { kind: 'ok', verified: recorded.pin.state === 'verified' }
  return { kind: 'ok', verified: false }
}

function okStatus(pin: IdentityPin): IdentityStatus {
  const formerly = formerOf(pin)
  return { kind: 'ok', verified: pin.state === 'verified', ...(formerly ? { formerly } : {}) }
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
      const match = await lookupIdentityPin(pins.pins, account, null)
      if (match.kind !== 'pinned') return null
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
 * Whether `account` is in the list (met before in Drive, Chat or the CLI).
 * Tells a Kutup account on another server from an ordinary email address
 * without asking that server: only a listed one is worth looking up.
 */
export async function isPinned(me: DriveIdentity, account: string): Promise<boolean> {
  const match = await lookupIdentityPin((await pinStore(me)).pins, account, null)
  return match.kind === 'pinned'
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
    readonly status: Extract<IdentityStatus, { kind: 'changed' | 'invalid' }>,
  ) {
    super(`the identity of ${account} could not be confirmed (${status.kind})`)
  }
}

/**
 * Before sealing anything to `account`: its keys checked as `checkIdentity`
 * does. A changed or invalid identity stops the share with
 * `IdentityNotConfirmed` until the user confirms (`confirmed`): Drive warns,
 * it does not refuse.
 */
export async function confirmRecipient(
  me: DriveIdentity,
  account: string,
  claimed: ClaimedKeys,
  confirmed = false,
): Promise<IdentityStatus> {
  const status = await checkIdentity(me, account, claimed)
  if ((status.kind === 'changed' || status.kind === 'invalid') && !confirmed) throw new IdentityNotConfirmed(account, status)
  return status
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
    account,
    person.accountAuthorityPublicKey,
    person.driveHpkePublicKey,
    person.driveSigningPublicKey,
    person.driveKeyBinding,
  )
  if (!bound) throw new Error('the keys are not signed by this account')
  const recorded = await recordPin(me, account, person.accountAuthorityPublicKey, 'accepted')
  // This identity is pinned under another address: the same person, renamed.
  // Following their rename chain moves the pin (it needs the rename lookups,
  // docs/plans/username-renames.md); accepting it here would pin them twice.
  if (recorded.kind === 'knownElsewhere') throw new IdentityKnownElsewhere(account, recorded.pin.account)
}

/** A person's published identity, once their binding is checked; throws otherwise. */
async function boundIdentity(me: DriveIdentity, account: string): Promise<PublishedIdentity> {
  const person = await publishedIdentity(me, account)
  const bound =
    Boolean(person.driveKeyBinding) &&
    (await verifyDriveKeyBinding(
      account,
      person.accountAuthorityPublicKey,
      person.driveHpkePublicKey,
      person.driveSigningPublicKey,
      person.driveKeyBinding!,
    ).catch(() => false))
  if (!bound) throw new IdentityUnproven(account)
  return person
}

/** The identity to accept is someone the list already knows under another address (`other`). */
export class IdentityKnownElsewhere extends Error {
  constructor(
    readonly account: string,
    readonly other: string,
  ) {
    super(`the identity at ${account} is already known as ${other}`)
  }
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
  return deriveSafetyNumber(me.authorityPublicKey, person.accountAuthorityPublicKey)
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
  const matches = await safetyQrMatches(me.authorityPublicKey, person.accountAuthorityPublicKey, scanned)
  if (!matches) throw new SafetyNumberMismatch()
  await recordPin(me, account, person.accountAuthorityPublicKey, 'verified')
}

/** Test seam: forget what this page has looked up and pinned. */
export function resetIdentityPinsForTesting(): void {
  published.clear()
  queued = []
  flushing = null
  store = null
  writes = Promise.resolve()
}
