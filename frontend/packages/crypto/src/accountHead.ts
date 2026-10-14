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

  close(): void {
    this.handle.free()
  }
}
