// The account head (docs/plans/rollback-protection.md): Rust owns the format,
// the digests and the checks (kutup-crypto account_head); this is the
// browser's door to them. One AccountHead per signed-in account: its keys,
// and the head this page verified, stay in WASM. Sealed heads travel as
// canonical base64.

import { toBase64 } from './base64'
import { getCryptoWasm, type AccountHeadKeysHandle, type VerifiedAccountHeadHandle } from './rustWasm'

/** One scope's entry: how many values, and the digest of their (id, revision) pairs. */
export interface HeadScope {
  scope: string
  count: number
  digest: string
}

export interface AccountHeadValue {
  incarnationId: string
  sequence: number
  previous?: string
  writer: string
  scopes: HeadScope[]
}

/** What a device remembers of a head. Only a check or a re-anchoring gives one. */
export interface HeadAnchor {
  sequence: number
  digest: string
}

/**
 * How the current head relates to what this device remembers:
 * - `fresh` (nothing remembered), `current`, `extends`: trusted;
 * - `rollback`, `fork`: blocking; the person decides (a restore from a backup
 *   looks the same) and may re-anchor;
 * - `tooOld`: the remembered head is further back than the server keeps:
 *   re-anchor with a notice.
 */
export type HeadStatus = { kind: 'fresh' | 'current' | 'extends' | 'rollback' | 'fork' | 'tooOld' }

/** What a device logs when it re-anchors. */
export interface Reanchored {
  from: HeadAnchor
  to: HeadAnchor
  status: HeadStatus
  atMs: number
}

/** Something a device notes about its anchor, newest last. */
export type LocalHeadEvent =
  | { kind: 'startedFresh'; anchor: HeadAnchor; atMs: number }
  | { kind: 'reanchored'; record: Reanchored }
  | { kind: 'forgotten'; from: HeadAnchor; atMs: number }

/**
 * What this device keeps for the account's current incarnation (Rust
 * `LocalHeadStateV1`): its anchor, its device id, and its log.
 */
export interface LocalHeadState {
  incarnationId: string
  deviceId: string
  anchor: HeadAnchor | null
  /** When the anchor last changed (Unix ms; 0: never). */
  anchoredAtMs: number
  log: LocalHeadEvent[]
}

/** A scope's index, as the server lists it: value ids and their revisions. */
export type HeadIndex = ReadonlyArray<readonly [string, number]>

/**
 * A head a check, a re-anchoring, or this page's own committed write
 * verified (Rust `VerifiedHead`). Each holder has its own: a check elsewhere
 * in the page cannot change the one a write is using. `free()` it when done.
 */
export class VerifiedHead {
  constructor(private readonly handle: VerifiedAccountHeadHandle) {}

  /** What to remember. */
  get anchor(): HeadAnchor {
    return this.handle.anchor() as HeadAnchor
  }

  get head(): AccountHeadValue {
    return this.handle.head() as AccountHeadValue
  }

  /** Another, independent handle to the same head. */
  copy(): VerifiedHead {
    return new VerifiedHead(this.handle.copy())
  }

  /** @internal */
  get raw(): VerifiedAccountHeadHandle {
    return this.handle
  }

  free(): void {
    this.handle.free()
  }
}

/** The account head's keys for one signed-in account. Call `close()` at sign-out. */
export class AccountHead {
  private constructor(private readonly handle: AccountHeadKeysHandle) {}

  static async open(masterKey: Uint8Array, binding: string, incarnationId: string): Promise<AccountHead> {
    const wasm = await getCryptoWasm()
    return new AccountHead(new wasm.AccountHeadKeys(toBase64(masterKey), binding, incarnationId))
  }

  writer(deviceId: string): string {
    return this.handle.writer(deviceId)
  }

  scope(scope: string, index: HeadIndex): HeadScope {
    return this.handle.scope(scope, JSON.stringify(index)) as HeadScope
  }

  /**
   * Checks `current` against `anchor`. `segment` is the chain from the anchor
   * to `current`, or null when the server did not show it. A trusted head
   * comes with its verified head, which the caller owns.
   */
  check(anchor: HeadAnchor | null, current: string, segment: readonly string[] | null): { status: HeadStatus; verified: VerifiedHead | null } {
    const checked = this.handle.check(anchor ? JSON.stringify(anchor) : undefined, current, segment ? JSON.stringify(segment) : undefined)
    try {
      const verified = checked.takeVerified()
      return { status: checked.status() as HeadStatus, verified: verified ? new VerifiedHead(verified) : null }
    } finally {
      checked.free()
    }
  }

  /** Re-anchors after a check did not trust the head (`rollback`/`fork` only when the person `confirmed`): the record to log, and the head now verified. */
  reanchor(anchor: HeadAnchor, current: string, segment: readonly string[] | null, confirmed: boolean, atMs = Date.now()): { record: Reanchored; verified: VerifiedHead } {
    const result = this.handle.reanchor(JSON.stringify(anchor), current, segment ? JSON.stringify(segment) : undefined, confirmed, atMs)
    try {
      return { record: result.record() as Reanchored, verified: new VerifiedHead(result.takeVerified()!) }
    } finally {
      result.free()
    }
  }

  /** `matches`, or `uncovered` (the head does not cover the scope yet); throws if it differs. */
  checkIndex(verified: VerifiedHead, scope: string, index: HeadIndex): 'matches' | 'uncovered' {
    return this.handle.checkIndex(verified.raw, scope, JSON.stringify(index)) as 'matches' | 'uncovered'
  }

  /** The next head, sealed, on top of `verified`. */
  next(verified: VerifiedHead, writer: string, scopes: readonly HeadScope[]): string {
    return this.handle.next(verified.raw, writer, JSON.stringify(scopes))
  }

  /** The account's first head, sealed (the server has none yet). */
  first(writer: string, scopes: readonly HeadScope[]): string {
    return this.handle.first(writer, JSON.stringify(scopes))
  }

  /** After the server stored `sealed` on top of `verified` (or as the first head, with null): the newly verified head. */
  committed(verified: VerifiedHead | null, sealed: string): VerifiedHead {
    return new VerifiedHead(verified ? this.handle.committed(verified.raw, sealed) : this.handle.committedFirst(sealed))
  }

  /** The name this device stores its state under: one per account and incarnation. */
  localStateName(): string {
    return this.handle.localStateName()
  }

  /** A device's state before it has seen any head, with a new random device id. */
  newLocalState(): LocalHeadState {
    return this.handle.newLocalState() as LocalHeadState
  }

  /** Opens this device's stored state; throws when it does not open (then start fresh). */
  openLocalState(sealed: string): LocalHeadState {
    return this.handle.openLocalState(sealed) as LocalHeadState
  }

  sealLocalState(state: LocalHeadState): string {
    return this.handle.sealLocalState(JSON.stringify(state))
  }

  /** Moves the anchor to `verified`, never back. */
  advanceLocalState(state: LocalHeadState, verified: VerifiedHead, atMs: number): { state: LocalHeadState; changed: boolean } {
    return this.handle.advanceLocalState(JSON.stringify(state), verified.raw, atMs) as { state: LocalHeadState; changed: boolean }
  }

  /** After `reanchor`: the anchor moves to its head (`verified`, which it gave), and the record is logged. */
  reanchoredLocalState(state: LocalHeadState, record: Reanchored, verified: VerifiedHead): LocalHeadState {
    return this.handle.reanchoredLocalState(JSON.stringify(state), JSON.stringify(record), verified.raw) as LocalHeadState
  }

  /** The server has no head at all and the person confirmed going on: the anchor is dropped, logged. */
  forgottenLocalState(state: LocalHeadState, atMs: number): LocalHeadState {
    return this.handle.forgottenLocalState(JSON.stringify(state), atMs) as LocalHeadState
  }

  close(): void {
    this.handle.free()
  }
}
