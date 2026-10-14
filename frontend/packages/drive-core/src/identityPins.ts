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
import {
  deriveSafetyNumber,
  incarnationIdOfAuthority,
  openIdentityPins,
  EMPTY_PINS,
  recordIdentityPin,
  safetyQrMatches,
  sealIdentityPins,
  verifyDriveKeyBinding,
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
 * - `unknown`: could not be checked (no connection, the lookup failed).
 */
export type IdentityStatus =
  | { kind: 'ok'; verified: boolean }
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

// -------------------------------------------------------------- checks

/**
 * How far `account`'s `claimed` keys can be trusted; pins the account's
 * authority the first time it is met with a valid binding.
 */
export async function checkIdentity(me: DriveIdentity, account: string, claimed: ClaimedKeys = {}): Promise<IdentityStatus> {
  if (account === me.account) return { kind: 'ok', verified: true }
  let person: PublishedIdentity
  try {
    person = await publishedIdentity(me, account)
  } catch {
    return { kind: 'unknown' }
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
  const pin = pins.pins.list.pins.find((known) => known.account === account)
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
    if (pin.authorityPublicKey === person.accountAuthorityPublicKey) return { kind: 'ok', verified: pin.state === 'verified' }
    return { kind: 'changed' }
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

/**
 * Whether `account` is in the list (met before in Drive, Chat or the CLI).
 * Tells a Kutup account on another server from an ordinary email address
 * without asking that server: only a listed one is worth looking up.
 */
export async function isPinned(me: DriveIdentity, account: string): Promise<boolean> {
  return (await pinStore(me)).pins.list.pins.some((pin) => pin.account === account)
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
