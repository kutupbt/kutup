// The account head (docs/plans/rollback-protection.md): Rust owns the format,
// the digests and the checks (kutup-crypto account_head); this is the
// browser's door to them. One AccountHead per signed-in account: its keys,
// and the head this page verified, stay in WASM. Sealed heads travel as
// canonical base64.

import { toBase64 } from './base64'
import { getCryptoWasm, type AccountHeadKeysHandle } from './rustWasm'

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

/** The account head for one signed-in account. Call `close()` at sign-out. */
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
   * becomes the verified one, and `anchor` is what to remember.
   */
  check(anchor: HeadAnchor | null, current: string, segment: readonly string[] | null): { status: HeadStatus; anchor?: HeadAnchor } {
    return this.handle.check(anchor ? JSON.stringify(anchor) : undefined, current, segment ? JSON.stringify(segment) : undefined) as {
      status: HeadStatus
      anchor?: HeadAnchor
    }
  }

  /** Re-anchors after a check did not trust the head (`rollback`/`fork` only when the person `confirmed`); the record to log. */
  reanchor(anchor: HeadAnchor, current: string, segment: readonly string[] | null, confirmed: boolean): Reanchored {
    return this.handle.reanchor(JSON.stringify(anchor), current, segment ? JSON.stringify(segment) : undefined, confirmed, Date.now()) as Reanchored
  }

  /** `matches`, or `uncovered` (the head does not cover the scope yet); throws if it differs or no head is verified. */
  checkIndex(scope: string, index: HeadIndex): 'matches' | 'uncovered' {
    return this.handle.checkIndex(scope, JSON.stringify(index)) as 'matches' | 'uncovered'
  }

  /** The next head, sealed, on top of the verified one. */
  next(writer: string, scopes: readonly HeadScope[]): string {
    return this.handle.next(writer, JSON.stringify(scopes))
  }

  /** The account's first head, sealed (the server has none yet). */
  first(writer: string, scopes: readonly HeadScope[]): string {
    return this.handle.first(writer, JSON.stringify(scopes))
  }

  /** After the server stored `sealed`: it becomes the verified head; what to remember. */
  committed(sealed: string): HeadAnchor {
    return this.handle.committed(sealed) as HeadAnchor
  }

  verifiedHead(): AccountHeadValue | null {
    return this.handle.verifiedHead() as AccountHeadValue | null
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

  /** Moves the anchor to this page's verified head, never back. */
  advanceLocalState(state: LocalHeadState, atMs: number): { state: LocalHeadState; changed: boolean } {
    return this.handle.advanceLocalState(JSON.stringify(state), atMs) as { state: LocalHeadState; changed: boolean }
  }

  /** After `reanchor`: the anchor moves to its head, and the record is logged. */
  reanchoredLocalState(state: LocalHeadState, record: Reanchored): LocalHeadState {
    return this.handle.reanchoredLocalState(JSON.stringify(state), JSON.stringify(record)) as LocalHeadState
  }

  /** The server has no head at all and the person confirmed going on: the anchor is dropped, logged. */
  forgottenLocalState(state: LocalHeadState, atMs: number): LocalHeadState {
    return this.handle.forgottenLocalState(JSON.stringify(state), atMs) as LocalHeadState
  }

  close(): void {
    this.handle.free()
  }
}
