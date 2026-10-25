// Rollback protection across devices, the client half
// (docs/plans/rollback-protection.md). Rust owns the head, its checks and
// what a device keeps (kutup-crypto account_head, through
// @kutup/crypto/accountHead); this module sequences them against the API:
// - every read of a listed value goes through a verified index, so a value
//   rolled back, dropped or brought back is refused, even one this app never
//   saw before;
// - every listed write goes through `listedWrite`, which writes the next head
//   in the same request (and starts the chain when there is none);
// - a head that does not descend from what this app remembers blocks listed
//   writes until the person decides ("continue with the server's data").
//
// Each app origin is its own device (its own IndexedDB): its own anchor, its
// own writer tag, its own fork state. The state is one sealed record per
// account and incarnation, so two accounts in one browser, or an account
// before and after a reset, never share or compare anchors.

import { isAxiosError } from 'axios'
import {
  AccountHead,
  type AccountHeadValue,
  type HeadAnchor,
  type HeadIndex,
  type HeadScope,
  type HeadStatus,
  type LocalHeadState,
  type Reanchored,
} from '@kutup/crypto/accountHead'
import { fromBase64, toBase64 } from '@kutup/crypto/base64'
import { deriveAccountIdentityKeys } from '@kutup/crypto/identity'
import { indexedDbRevisionStore, type RevisionStore } from '@kutup/crypto/revisionGuard'
import api from './client'
import { getSession, subscribe } from './store'
import { hash } from '@kutup/crypto/hash'

/** A verified head (`@kutup/crypto/accountHead` `VerifiedHead`): each holder its own, freed when done. */
export interface VerifiedHeadLike {
  readonly anchor: HeadAnchor
  readonly head: AccountHeadValue
  copy(): VerifiedHeadLike
  free(): void
}

/** What this module needs of the Rust head (an `AccountHead`; tests use a fake). */
export interface HeadEngine {
  writer(deviceId: string): string
  scope(scope: string, index: HeadIndex): HeadScope
  check(anchor: HeadAnchor | null, current: string, segment: readonly string[] | null): { status: HeadStatus; verified: VerifiedHeadLike | null }
  reanchor(
    anchor: HeadAnchor,
    current: string,
    segment: readonly string[] | null,
    confirmed: boolean,
    atMs: number,
  ): { record: Reanchored; verified: VerifiedHeadLike }
  checkIndex(verified: VerifiedHeadLike, scope: string, index: HeadIndex): 'matches' | 'uncovered'
  next(verified: VerifiedHeadLike, writer: string, scopes: readonly HeadScope[]): string
  first(writer: string, scopes: readonly HeadScope[]): string
  committed(verified: VerifiedHeadLike | null, sealed: string): VerifiedHeadLike
  localStateName(): string
  newLocalState(): LocalHeadState
  openLocalState(sealed: string): LocalHeadState
  sealLocalState(state: LocalHeadState): string
  advanceLocalState(state: LocalHeadState, verified: VerifiedHeadLike, atMs: number): { state: LocalHeadState; changed: boolean }
  reanchoredLocalState(state: LocalHeadState, record: Reanchored, verified: VerifiedHeadLike): LocalHeadState
  forgottenLocalState(state: LocalHeadState, atMs: number): LocalHeadState
  close(): void
}

/** The kinds of value the head covers (the server's scope names). */
export type HeadScopeName = 'contacts' | 'mailNames' | 'pins' | 'passSecrets' | (string & {})

/**
 * Where this app stands with the account's history:
 * - `unknown`: not checked yet;
 * - `trusted`: the head descends from what this app remembers (or it trusted
 *   the first it saw);
 * - `blocked`: rolled back or forked; listed writes stop until the person
 *   decides.
 */
export type HeadCondition =
  | { kind: 'unknown' }
  | { kind: 'trusted'; notice: 'tooOld' | null }
  | { kind: 'blocked'; reason: 'rollback' | 'fork' }

/** Listed writes stop: the server showed another history (or an older one). */
export class HeadBlockedError extends Error {
  constructor(readonly reason: 'rollback' | 'fork') {
    super(`the account's history on the server is not the one this app knows (${reason})`)
    this.name = 'HeadBlockedError'
  }
}

/** A scope's index does not match the verified head: the server's list cannot be trusted. */
export class IndexMismatchError extends Error {
  constructor(readonly scope: string) {
    super(`${scope}: the server's list does not match the account's verified state`)
    this.name = 'IndexMismatchError'
  }
}

/** A value, or a listing, the verified index does not vouch for (rolled back, dropped or brought back). */
export class NotInVerifiedIndexError extends Error {
  constructor(
    readonly scope: string,
    readonly id: string | null,
  ) {
    super(id === null ? `${scope}: the listing is not the verified one` : `${scope}/${id}: not the verified revision`)
    this.name = 'NotInVerifiedIndexError'
  }
}

/** A scope's values as the verified head vouches for them. */
export class VerifiedIndex {
  private readonly revisions: ReadonlyMap<string, number>

  constructor(
    readonly scope: string,
    /** The head covers the scope: values outside it, or at another revision, are refused. */
    readonly covered: boolean,
    readonly values: HeadIndex,
    /** The server has no head yet: the chain starts on this basis. */
    readonly basis: string | null,
  ) {
    this.revisions = new Map(values.map(([id, revision]) => [id, revision]))
  }

  /** The revision the index lists for `id` (undefined: none). */
  revision(id: string): number | undefined {
    return this.revisions.get(id)
  }

  /** Refuses a value whose revision is not the one the covered index lists. */
  expect(id: string, revision: number): void {
    if (this.covered && this.revisions.get(id) !== revision) throw new NotInVerifiedIndexError(this.scope, id)
  }

  /**
   * Refuses a listing whose ids are not exactly the covered index's, or,
   * with `prefix`, exactly its ids that start with it (one kind of a scope
   * that holds several: `folder:` of `mailNames`).
   */
  expectListing(ids: Iterable<string>, prefix?: string): void {
    if (!this.covered) return
    const expected = prefix === undefined ? this.revisions.size : [...this.revisions.keys()].filter((id) => id.startsWith(prefix)).length
    const seen = new Set<string>()
    for (const id of ids) {
      if (!this.revisions.has(id) || seen.has(id) || (prefix !== undefined && !id.startsWith(prefix))) {
        throw new NotInVerifiedIndexError(this.scope, null)
      }
      seen.add(id)
    }
    if (seen.size !== expected) throw new NotInVerifiedIndexError(this.scope, null)
  }
}

/** A listed write: what it changes in the scope's index, and how to send it with its head. */
export interface ListedEdit<T> {
  /** Each id's new revision, or null when the write removes it. */
  changes: ReadonlyArray<readonly [string, number | null]>
  send(head: string): Promise<T>
}

/** What Account → Security shows ("Data state"). */
export interface DataState {
  sequence: number | null
  /** The verified head was written by this app. */
  lastByThisApp: boolean | null
  /** When this app last moved its anchor (local; the head holds no time). */
  anchoredAtMs: number | null
  log: LocalHeadState['log']
}

/** Something to tell the person about this app's state, for the shell's banner. */
export type HeadListener = (condition: HeadCondition) => void

interface Http {
  get<T>(url: string): Promise<{ data: T }>
  post<T>(url: string, body: unknown): Promise<{ data: T }>
}

/** How long a verified head is trusted without asking the server again. */
const VERIFIED_FOR_MS = 30_000
/** Every listed write is tried at most this many times (another device writing first). */
const WRITE_TRIES = 5

function conflictCode(error: unknown): string | null {
  if (!isAxiosError(error) || error.response?.status !== 409) return null
  return (error.response.data as { code?: string } | undefined)?.code ?? null
}

function statusOf(error: unknown): number | undefined {
  return isAxiosError(error) ? error.response?.status : undefined
}

async function sha256Hex(sealed: string): Promise<string> {
  const digest = await hash(new Uint8Array(fromBase64(sealed)))
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

/** The index after `changes`: new revisions set, removed ids dropped. */
function applied(values: HeadIndex, changes: ListedEdit<unknown>['changes']): HeadIndex {
  const next = new Map(values.map(([id, revision]) => [id, revision]))
  for (const [id, revision] of changes) {
    if (revision === null) next.delete(id)
    else next.set(id, revision)
  }
  return [...next.entries()]
}

/** Runs `task` under this origin's lock of `name` (other tabs wait), where the browser has locks. */
function locked<T>(name: string, task: () => Promise<T>): Promise<T> {
  const locks = typeof navigator !== 'undefined' ? navigator.locks : undefined
  return locks ? (locks.request(`kutup-account-head:${name}`, task) as Promise<T>) : task()
}

/** What one check of a head found. */
type Inspected =
  | { kind: 'trusted'; verified: VerifiedHeadLike | null; notice: 'tooOld' | null }
  | { kind: 'blocked'; reason: 'rollback' | 'fork'; on: NonNullable<AccountHeadClient['blockedOn']> }

export class AccountHeadClient {
  private condition: HeadCondition = { kind: 'unknown' }
  /** What "continue with the server's data" needs, while blocked. */
  private blockedOn: { current: string; segment: readonly string[] | null } | { forget: true } | null = null
  private verifiedAt = 0
  /** The latest head this page verified (its own copy), for the data state. */
  private latest: VerifiedHeadLike | null = null
  private writes: Promise<unknown> = Promise.resolve()
  private readonly listeners = new Set<HeadListener>()

  constructor(
    private readonly engine: HeadEngine,
    private readonly store: RevisionStore,
    private readonly http: Http = api,
    private readonly now: () => number = Date.now,
  ) {}

  private get entry(): string {
    return `account-head:${this.engine.localStateName()}`
  }

  subscribe(listener: HeadListener): () => void {
    this.listeners.add(listener)
    listener(this.condition)
    return () => this.listeners.delete(listener)
  }

  current(): HeadCondition {
    return this.condition
  }

  private set(condition: HeadCondition): void {
    this.condition = condition
    for (const listener of this.listeners) listener(condition)
  }

  /** This device's state; one that does not open (or none) is a fresh one. */
  private async load(): Promise<LocalHeadState> {
    const sealed = await this.store.get(this.entry)
    if (sealed) {
      try {
        return this.engine.openLocalState(sealed)
      } catch {
        // Altered, moved or another format: a fresh device, as a cleared one
        // is; the anchor this app then trusts is logged as started fresh.
      }
    }
    return this.engine.newLocalState()
  }

  private async save(state: LocalHeadState): Promise<void> {
    await this.store.put(this.entry, this.engine.sealLocalState(state))
  }

  /** `verified` becomes this page's latest, and the anchor moves to it (never back). */
  private async remember(verified: VerifiedHeadLike): Promise<void> {
    await locked(this.engine.localStateName(), async () => {
      const advanced = this.engine.advanceLocalState(await this.load(), verified, this.now())
      if (advanced.changed) await this.save(advanced.state)
    })
    this.latest?.free()
    this.latest = verified.copy()
    this.verifiedAt = this.now()
  }

  /** The chain from `from`, every page of it, cut at `current` (null when past the server's window). */
  private async segment(from: number, current: string): Promise<string[] | null> {
    const heads: string[] = []
    let next: number | null = from
    try {
      while (next !== null) {
        const page: { heads: string[]; next: number | null } = (
          await this.http.get<{ heads: string[]; next: number | null }>(`/account/heads?from=${next}`)
        ).data
        heads.push(...page.heads)
        // The chain up to the head being checked: one written since does not belong.
        const at = heads.indexOf(current)
        if (at >= 0) return heads.slice(0, at + 1)
        next = page.next
      }
    } catch (error) {
      // Past the server's window: the check tells too old from a fork.
      if (statusOf(error) === 410) return null
      throw error
    }
    return heads
  }

  /**
   * One check of the head the server shows (`current`; null: none) against
   * what this app remembers. Trusted: the verified head (the caller owns it),
   * and the anchor moved; too old: re-anchored with a notice.
   */
  private async inspect(current: string | null): Promise<Inspected> {
    return locked(this.engine.localStateName(), async (): Promise<Inspected> => {
      const state = await this.load()
      if (current === null) {
        if (state.anchor) return { kind: 'blocked', reason: 'rollback', on: { forget: true } }
        return { kind: 'trusted', verified: null, notice: null }
      }
      const anchor = state.anchor
      const segment = anchor && (await sha256Hex(current)) !== anchor.digest ? await this.segment(anchor.sequence, current) : null
      const { status, verified } = this.engine.check(anchor, current, segment)
      switch (status.kind) {
        case 'fresh':
        case 'current':
        case 'extends': {
          const advanced = this.engine.advanceLocalState(state, verified!, this.now())
          if (advanced.changed) await this.save(advanced.state)
          return { kind: 'trusted', verified, notice: null }
        }
        case 'tooOld': {
          // Further back than the server keeps: neither shown nor refuted.
          // Re-anchored with a notice, never blocking (docs/plans §7).
          const moved = this.engine.reanchor(anchor!, current, segment, false, this.now())
          await this.save(this.engine.reanchoredLocalState(state, moved.record, moved.verified))
          return { kind: 'trusted', verified: moved.verified, notice: 'tooOld' }
        }
        case 'rollback':
        case 'fork':
          return { kind: 'blocked', reason: status.kind, on: { current, segment } }
      }
    })
  }

  /**
   * Reads a snapshot (`read`: what the server shows, and the head it goes
   * with) and checks its head. A rollback or fork is read once more first:
   * another tab or device moving on between two reads is not one. Then it
   * blocks ({@link HeadBlockedError}).
   */
  private async checked<T>(read: () => Promise<{ current: string | null; data: T }>): Promise<{ data: T; verified: VerifiedHeadLike | null }> {
    if (this.condition.kind === 'blocked') throw new HeadBlockedError(this.condition.reason)
    for (let attempt = 0; ; attempt++) {
      const snapshot = await read()
      const outcome = await this.inspect(snapshot.current)
      if (outcome.kind === 'trusted') {
        if (outcome.verified) {
          this.latest?.free()
          this.latest = outcome.verified.copy()
        }
        this.verifiedAt = this.now()
        if (outcome.notice || this.condition.kind !== 'trusted') this.set({ kind: 'trusted', notice: outcome.notice })
        return { data: snapshot.data, verified: outcome.verified }
      }
      if (attempt > 0) {
        this.blockedOn = outcome.on
        this.verifiedAt = 0
        this.set({ kind: 'blocked', reason: outcome.reason })
        throw new HeadBlockedError(outcome.reason)
      }
    }
  }

  /** The account's head, verified (asked again after a while, or after a write). */
  async verifiedHead(): Promise<void> {
    if (this.condition.kind === 'blocked') throw new HeadBlockedError(this.condition.reason)
    if (this.condition.kind === 'trusted' && this.now() - this.verifiedAt < VERIFIED_FOR_MS) return
    const { verified } = await this.checked(async () => ({ current: (await this.http.get<{ head: string | null }>('/account/head')).data.head, data: null }))
    verified?.free()
  }

  /**
   * A scope's index checked against the head it was read with (one
   * snapshot), and that verified head (the caller owns it). A scope the
   * server keeps no index of (404) is read as an empty index and checked like
   * any other: uncovered only when the verified head doesn't cover the scope
   * either, so a server can't hide a scope the head commits to.
   */
  private async readIndex(scope: HeadScopeName): Promise<{ index: VerifiedIndex; verified: VerifiedHeadLike | null }> {
    type Snapshot = { values: [string, number][]; basis: string | null; known: boolean }
    const { data, verified } = await this.checked<Snapshot>(async () => {
      try {
        const { data } = await this.http.get<{ head: string | null; values: [string, number][]; basis: string | null }>(
          `/account/index/${encodeURIComponent(scope)}`,
        )
        return { current: data.head, data: { values: data.values, basis: data.basis, known: true } }
      } catch (error) {
        if (statusOf(error) !== 404) throw error
        const { data } = await this.http.get<{ head: string | null }>('/account/head')
        return { current: data.head, data: { values: [], basis: null, known: false } }
      }
    })
    if (!verified) return { index: new VerifiedIndex(scope, false, data.values, data.known ? data.basis : null), verified }
    let covered: boolean
    try {
      covered = this.engine.checkIndex(verified, scope, data.values) === 'matches'
    } catch {
      verified.free()
      throw new IndexMismatchError(scope)
    }
    return { index: new VerifiedIndex(scope, covered, data.values, null), verified }
  }

  /** A scope's index, checked against the head it was read with. */
  async verifiedIndex(scope: HeadScopeName): Promise<VerifiedIndex> {
    const { index, verified } = await this.readIndex(scope)
    verified?.free()
    return index
  }

  /**
   * A listed write of `scope`: the edit is made against the verified index,
   * sent with the next head, and redone (up to five times) when another
   * device wrote first (`attempt` counts from 1: past the first, re-read the
   * value). The chain is started first when there is none. An edit that
   * returns null changes nothing and sends nothing. One listed write at a
   * time in this page, each on the head it verified itself: a check elsewhere
   * in the page cannot change it midway.
   */
  listedWrite<T>(scope: HeadScopeName, edit: (index: VerifiedIndex, attempt: number) => Promise<ListedEdit<T> | null>): Promise<T | undefined> {
    const run = () => this.write(scope, edit)
    const result = this.writes.then(run, run)
    this.writes = result.catch(() => undefined)
    return result
  }

  private async write<T>(
    scope: HeadScopeName,
    edit: (index: VerifiedIndex, attempt: number) => Promise<ListedEdit<T> | null>,
  ): Promise<T | undefined> {
    for (let attempt = 1; ; attempt++) {
      if (this.condition.kind === 'blocked') throw new HeadBlockedError(this.condition.reason)
      const { index, verified } = await this.readIndex(scope)
      let base = verified
      try {
        const writer = this.engine.writer((await this.load()).deviceId)
        const change = await edit(index, attempt)
        // Nothing to change (the edit found it already done): nothing is sent.
        if (change === null) return undefined
        if (index.basis !== null) {
          // No head yet: the chain starts on the index's basis, covering
          // every value; then this write follows it.
          const first = this.engine.first(writer, [this.engine.scope(scope, index.values)])
          await this.http.post('/account/head', { head: first, basis: index.basis })
          base = this.engine.committed(null, first)
          await this.remember(base)
        }
        if (!base) throw new Error('no verified account head to write on')
        const head = this.engine.next(base, writer, [this.engine.scope(scope, applied(index.values, change.changes))])
        const result = await change.send(head)
        try {
          const after = this.engine.committed(base, head)
          await this.remember(after)
          after.free()
        } catch {
          // Stored, but not taken as verified here: the next read checks it.
          this.verifiedAt = 0
        }
        return result
      } catch (error) {
        const code = conflictCode(error)
        if ((code === 'head_conflict' || code === 'revision_conflict') && attempt < WRITE_TRIES) continue
        throw error
      } finally {
        base?.free()
        if (verified && verified !== base) verified.free()
      }
    }
  }

  /**
   * "Continue with the server's data": the person confirmed moving this app
   * to the history the server shows (a restore from a backup looks the same as
   * a rollback). Logged locally; listed writes resume.
   */
  async continueWithServer(): Promise<void> {
    const on = this.blockedOn
    if (!on) return
    await locked(this.engine.localStateName(), async () => {
      const state = await this.load()
      if ('forget' in on) {
        await this.save(this.engine.forgottenLocalState(state, this.now()))
      } else if (state.anchor) {
        const moved = this.engine.reanchor(state.anchor, on.current, on.segment, true, this.now())
        await this.save(this.engine.reanchoredLocalState(state, moved.record, moved.verified))
        this.latest?.free()
        this.latest = moved.verified
      }
    })
    this.blockedOn = null
    this.verifiedAt = this.now()
    this.set({ kind: 'trusted', notice: null })
  }

  /** Clears the "too old" notice once shown. */
  dismissNotice(): void {
    if (this.condition.kind === 'trusted' && this.condition.notice) this.set({ kind: 'trusted', notice: null })
  }

  /** What Account → Security shows. */
  async dataState(): Promise<DataState> {
    const state = await this.load()
    const head = this.latest?.head ?? null
    return {
      sequence: state.anchor?.sequence ?? null,
      lastByThisApp: head ? head.writer === this.engine.writer(state.deviceId) : null,
      anchoredAtMs: state.anchor ? state.anchoredAtMs : null,
      log: state.log,
    }
  }

  close(): void {
    this.latest?.free()
    this.latest = null
    this.engine.close()
    this.listeners.clear()
  }
}

/** An engine that opens the Rust head on first use (the master key crosses once). */
function lazyEngine(masterKey: Uint8Array, binding: string): Promise<HeadEngine> {
  return (async () => {
    const { incarnationId } = await deriveAccountIdentityKeys(toBase64(masterKey))
    return AccountHead.open(masterKey, binding, incarnationId)
  })()
}

let shared: RevisionStore | null = null
const clients = new Map<string, { masterKey: string; client: Promise<AccountHeadClient> }>()

/**
 * The account's head client for this page: one per signed-in account (made
 * again when the master key changes), over this origin's store.
 */
export function accountHead(session: { userId: string; masterKey: Uint8Array; envelopeBinding: string }): Promise<AccountHeadClient> {
  const masterKey = toBase64(session.masterKey)
  const known = clients.get(session.userId)
  if (known?.masterKey === masterKey) return known.client
  if (known) void known.client.then((client) => client.close(), () => undefined)
  watchSignOut()
  shared ??= indexedDbRevisionStore()
  const store = shared
  const client = lazyEngine(session.masterKey, session.envelopeBinding).then((engine) => new AccountHeadClient(engine, store))
  // Not kept when it failed: the next call tries again.
  client.catch(() => {
    if (clients.get(session.userId)?.client === client) clients.delete(session.userId)
  })
  clients.set(session.userId, { masterKey, client })
  return client
}

/** Closes every account's head client (sign-out). */
export function closeAccountHeads(): void {
  for (const { client } of clients.values()) void client.then((c) => c.close(), () => undefined)
  clients.clear()
}

// Signed out (any path: a sign-out, a refused refresh, another tab's): the
// head keys go with the session.
let watching = false
function watchSignOut(): void {
  if (watching) return
  watching = true
  subscribe(() => {
    if (!getSession() && clients.size > 0) closeAccountHeads()
  })
}
