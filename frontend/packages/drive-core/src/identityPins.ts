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
  safetyQrMatches,
  sealIdentityPins,
  verifyDriveKeyBinding,
  type IdentityPin,
  type IdentityPins,
} from '@kutup/crypto/identityPins'
import { toBase64 } from '@kutup/crypto'
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
  pins: Map<string, IdentityPin>
}

let store: { userId: string; loaded: Promise<PinStore> } | null = null
let writes: Promise<unknown> = Promise.resolve()

const highestKey = (userId: string) => `kutup-identity-pins-revision:${userId}`

/** The highest revision this browser has seen: a server cannot quietly hand back an older list. */
function highestSeen(userId: string): number {
  try {
    return Number(localStorage.getItem(highestKey(userId)) ?? '0') || 0
  } catch {
    return 0
  }
}

function remember(userId: string, revision: number) {
  try {
    if (revision > highestSeen(userId)) localStorage.setItem(highestKey(userId), String(revision))
  } catch {
    // Without storage, only the server's word: still sealed and authenticated.
  }
}

export class PinsRolledBack extends Error {
  constructor() {
    super('the server returned an older identity pin list than this browser has seen')
  }
}

async function fetchPins(me: DriveIdentity): Promise<PinStore> {
  let data: { revision: number; envelope: string } | null = null
  try {
    data = (await api.get<{ revision: number; envelope: string }>('/user/identity-pins')).data
  } catch (error) {
    if (!(isAxiosError(error) && error.response?.status === 404)) throw error
  }
  const revision = data?.revision ?? 0
  if (revision < highestSeen(me.userId)) throw new PinsRolledBack()
  const list: IdentityPins = data ? await openIdentityPins(toBase64(me.masterKey), me.account, data.revision, data.envelope) : { pins: [] }
  remember(me.userId, revision)
  return { revision, pins: new Map(list.pins.map((pin) => [pin.account, pin])) }
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
 * Applies `change` to the list and stores it as the next revision; when
 * another app stored one first, starts again from that one. One write at a
 * time from this page.
 */
function updatePins(me: DriveIdentity, change: (pins: Map<string, IdentityPin>) => boolean | Promise<boolean>): Promise<void> {
  const run = async () => {
    for (let attempt = 0; attempt < 5; attempt++) {
      const current = await pinStore(me)
      const next = new Map(current.pins)
      if (!(await change(next))) return
      const revision = current.revision + 1
      const list: IdentityPins = { pins: [...next.values()].sort((a, b) => (a.account < b.account ? -1 : 1)) }
      const envelope = await sealIdentityPins(toBase64(me.masterKey), me.account, revision, list)
      try {
        await api.put('/user/identity-pins', { revision, envelope })
        remember(me.userId, revision)
        store = { userId: me.userId, loaded: Promise.resolve({ revision, pins: next }) }
        return
      } catch (error) {
        if (!(isAxiosError(error) && error.response?.status === 409)) throw error
        store = null
      }
    }
    throw new Error('the identity pin list kept changing')
  }
  const result = writes.then(run, run)
  writes = result.catch(() => undefined)
  return result
}

function now(): string {
  return new Date().toISOString()
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
  const pin = pins.pins.get(account)
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
  // First met: trusted from now on.
  await updatePins(me, (next) => {
    if (next.has(account)) return false
    next.set(account, { account, authorityPublicKey: person.accountAuthorityPublicKey, state: 'seen', since: now() })
    return true
  }).catch(() => undefined)
  return { kind: 'ok', verified: false }
}

/**
 * Whether `account` is in the list (met before in Drive, Chat or the CLI).
 * Tells a Kutup account on another server from an ordinary email address
 * without asking that server: only a listed one is worth looking up.
 */
export async function isPinned(me: DriveIdentity, account: string): Promise<boolean> {
  return (await pinStore(me)).pins.has(account)
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
  await updatePins(me, async (next) => {
    const previous = next.get(account)
    if (previous?.authorityPublicKey === person.accountAuthorityPublicKey) return false
    const replaced = previous ? [...(previous.replaced ?? [])] : []
    if (previous) replaced.push(await incarnationIdOfAuthority(previous.authorityPublicKey))
    next.set(account, {
      account,
      authorityPublicKey: person.accountAuthorityPublicKey,
      state: 'seen',
      since: now(),
      ...(replaced.length ? { replaced: replaced.slice(-10) } : {}),
    })
    return true
  })
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
  return deriveSafetyNumber(me.account, me.authorityPublicKey, account, person.accountAuthorityPublicKey)
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
  const matches = await safetyQrMatches(me.account, me.authorityPublicKey, account, person.accountAuthorityPublicKey, scanned)
  if (!matches) throw new SafetyNumberMismatch()
  await updatePins(me, async (next) => {
    const previous = next.get(account)
    if (previous?.authorityPublicKey === person.accountAuthorityPublicKey && previous.state === 'verified') return false
    const replaced = [...(previous?.replaced ?? [])]
    if (previous && previous.authorityPublicKey !== person.accountAuthorityPublicKey) {
      replaced.push(await incarnationIdOfAuthority(previous.authorityPublicKey))
    }
    next.set(account, {
      account,
      authorityPublicKey: person.accountAuthorityPublicKey,
      state: 'verified',
      since: now(),
      ...(replaced.length ? { replaced: replaced.slice(-10) } : {}),
    })
    return true
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
