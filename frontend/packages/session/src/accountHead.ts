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

/** What this module needs of the Rust head (an `AccountHead`; tests use a fake). */
export interface HeadEngine {
  writer(deviceId: string): string
  scope(scope: string, index: HeadIndex): HeadScope
  check(anchor: HeadAnchor | null, current: string, segment: readonly string[] | null): { status: HeadStatus; anchor?: HeadAnchor }
  reanchor(anchor: HeadAnchor, current: string, segment: readonly string[] | null, confirmed: boolean, atMs: number): Reanchored
  checkIndex(scope: string, index: HeadIndex): 'matches' | 'uncovered'
  next(writer: string, scopes: readonly HeadScope[]): string
  first(writer: string, scopes: readonly HeadScope[]): string
  committed(sealed: string): HeadAnchor
  verifiedHead(): AccountHeadValue | null
  localStateName(): string
  newLocalState(): LocalHeadState
  openLocalState(sealed: string): LocalHeadState
  sealLocalState(state: LocalHeadState): string
  advanceLocalState(state: LocalHeadState, atMs: number): { state: LocalHeadState; changed: boolean }
  reanchoredLocalState(state: LocalHeadState, record: Reanchored): LocalHeadState
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

  /** Refuses a listing whose ids are not exactly the covered index's. */
  expectListing(ids: Iterable<string>): void {
    if (!this.covered) return
    const seen = new Set<string>()
    for (const id of ids) {
      if (!this.revisions.has(id) || seen.has(id)) throw new NotInVerifiedIndexError(this.scope, null)
      seen.add(id)
    }
    if (seen.size !== this.revisions.size) throw new NotInVerifiedIndexError(this.scope, null)
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
  // A copy on its own ArrayBuffer, as Web Crypto takes.
  const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(fromBase64(sealed)))
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
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

export class AccountHeadClient {
  private condition: HeadCondition = { kind: 'unknown' }
  /** What "continue with the server's data" needs, while blocked. */
  private blockedOn: { current: string; segment: readonly string[] | null } | { forget: true } | null = null
  private verifiedAt = 0
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

  private async segment(from: number): Promise<string[] | null> {
    const heads: string[] = []
    let next: number | null = from
    try {
      while (next !== null) {
        const page: { heads: string[]; next: number | null } = (
          await this.http.get<{ heads: string[]; next: number | null }>(`/account/heads?from=${next}`)
        ).data
        heads.push(...page.heads)
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
   * Checks the head the server shows (`current`; null: none) against what
   * this app remembers, and remembers it when trusted. Throws
   * {@link HeadBlockedError} for a rollback or a fork.
   */
  private async verify(current: string | null): Promise<void> {
    await locked(this.engine.localStateName(), async () => {
      const state = await this.load()
      if (current === null) {
        if (state.anchor) return this.block('rollback', { forget: true })
        this.verifiedAt = this.now()
        if (this.condition.kind !== 'trusted') this.set({ kind: 'trusted', notice: null })
        return
      }
      const anchor = state.anchor
      const segment = anchor && (await sha256Hex(current)) !== anchor.digest ? await this.segment(anchor.sequence) : null
      const { status } = this.engine.check(anchor, current, segment)
      switch (status.kind) {
        case 'fresh':
        case 'current':
        case 'extends': {
          const advanced = this.engine.advanceLocalState(state, this.now())
          if (advanced.changed) await this.save(advanced.state)
          this.verifiedAt = this.now()
          if (this.condition.kind !== 'trusted') this.set({ kind: 'trusted', notice: null })
          return
        }
        case 'tooOld': {
          // Further back than the server keeps: neither shown nor refuted.
          // Re-anchored with a notice, never blocking (docs/plans §7).
          const record = this.engine.reanchor(anchor!, current, segment, false, this.now())
          await this.save(this.engine.reanchoredLocalState(state, record))
          this.verifiedAt = this.now()
          this.set({ kind: 'trusted', notice: 'tooOld' })
          return
        }
        case 'rollback':
        case 'fork':
          return this.block(status.kind, { current, segment })
      }
    })
  }

  private block(reason: 'rollback' | 'fork', on: NonNullable<AccountHeadClient['blockedOn']>): never {
    this.blockedOn = on
    this.verifiedAt = 0
    this.set({ kind: 'blocked', reason })
    throw new HeadBlockedError(reason)
  }

  /** The account's head, verified (asked again after a while, or after a write). */
  async verifiedHead(): Promise<void> {
    if (this.condition.kind === 'blocked') throw new HeadBlockedError(this.condition.reason)
    if (this.condition.kind === 'trusted' && this.now() - this.verifiedAt < VERIFIED_FOR_MS) return
    const { data } = await this.http.get<{ head: string | null }>('/account/head')
    await this.verify(data.head)
  }

  /**
   * A scope's index, checked against the head it was read with (one
   * snapshot). A scope the server keeps no index of yet (404) is uncovered.
   */
  async verifiedIndex(scope: HeadScopeName): Promise<VerifiedIndex> {
    let data: { head: string | null; values: [string, number][]; basis: string | null }
    try {
      data = (await this.http.get<typeof data>(`/account/index/${encodeURIComponent(scope)}`)).data
    } catch (error) {
      if (statusOf(error) !== 404) throw error
      await this.verifiedHead()
      return new VerifiedIndex(scope, false, [], null)
    }
    await this.verify(data.head)
    if (data.head === null) return new VerifiedIndex(scope, false, data.values, data.basis)
    let covered: boolean
    try {
      covered = this.engine.checkIndex(scope, data.values) === 'matches'
    } catch {
      throw new IndexMismatchError(scope)
    }
    return new VerifiedIndex(scope, covered, data.values, null)
  }

  /** The head the server stored for this app's write becomes the verified one and the anchor. */
  private async commit(sealed: string): Promise<void> {
    this.engine.committed(sealed)
    await locked(this.engine.localStateName(), async () => {
      const advanced = this.engine.advanceLocalState(await this.load(), this.now())
      if (advanced.changed) await this.save(advanced.state)
    })
    this.verifiedAt = this.now()
  }

  /**
   * A listed write of `scope`: the edit is made against the verified index,
   * sent with the next head, and redone (up to five times) when another
   * device wrote first. The chain is started first when there is none. One
   * listed write at a time in this page.
   */
  listedWrite<T>(scope: HeadScopeName, edit: (index: VerifiedIndex) => Promise<ListedEdit<T>>): Promise<T> {
    const run = () => this.write(scope, edit)
    const result = this.writes.then(run, run)
    this.writes = result.catch(() => undefined)
    return result
  }

  private async write<T>(scope: HeadScopeName, edit: (index: VerifiedIndex) => Promise<ListedEdit<T>>): Promise<T> {
    for (let attempt = 1; ; attempt++) {
      if (this.condition.kind === 'blocked') throw new HeadBlockedError(this.condition.reason)
      // Every attempt reads the index again: an earlier one met a newer head.
      this.verifiedAt = 0
      const index = await this.verifiedIndex(scope)
      const state = await this.load()
      const writer = this.engine.writer(state.deviceId)
      try {
        if (index.basis !== null) {
          // No head yet: the chain starts on the index's basis, covering
          // every value; then this write follows it.
          const first = this.engine.first(writer, [this.engine.scope(scope, index.values)])
          await this.http.post('/account/head', { head: first, basis: index.basis })
          await this.commit(first)
        }
        const change = await edit(index)
        const head = this.engine.next(writer, [this.engine.scope(scope, applied(index.values, change.changes))])
        const result = await change.send(head)
        await this.commit(head)
        return result
      } catch (error) {
        const code = conflictCode(error)
        if ((code === 'head_conflict' || code === 'revision_conflict') && attempt < WRITE_TRIES) continue
        throw error
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
        const record = this.engine.reanchor(state.anchor, on.current, on.segment, true, this.now())
        await this.save(this.engine.reanchoredLocalState(state, record))
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
    const head = this.engine.verifiedHead()
    return {
      sequence: state.anchor?.sequence ?? null,
      lastByThisApp: head ? head.writer === this.engine.writer(state.deviceId) : null,
      anchoredAtMs: state.anchor ? state.anchoredAtMs : null,
      log: state.log,
    }
  }

  close(): void {
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
