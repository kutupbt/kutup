// The account head (docs/plans/rollback-protection.md): Rust owns the format,
// the digests and the checks (kutup-crypto account_head); this is the
// browser's door to them. Sealed heads travel as canonical base64.

import { toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

/** One scope's entry: how many values, and the digest of their (id, revision) pairs. */
export interface HeadScope {
  scope: string
  count: number
  digest: string
}

export interface AccountHead {
  incarnationId: string
  sequence: number
  previous?: string
  writer: string
  scopes: HeadScope[]
}

/** What a device remembers of a head. */
export interface HeadAnchor {
  sequence: number
  digest: string
}

/**
 * How the current head relates to what this device remembers:
 * `fresh` (nothing remembered), `current`, `extends`; `rollback` and `fork`
 * (blocking: the person decides, a restore from a backup looks the same);
 * `tooOld` (the remembered head is older than the chain the server keeps:
 * re-anchor with a notice).
 */
export type HeadStatus = { kind: 'fresh' | 'current' | 'extends' | 'rollback' | 'fork' | 'tooOld' }

/** What a device logs when it re-anchors. */
export interface Reanchored {
  from?: HeadAnchor | null
  to: HeadAnchor
  reason: 'fresh' | 'tooOld' | 'rollback' | 'fork'
  atMs: number
}

/** A scope's index, as the server lists it: value ids and their revisions. */
export type HeadIndex = ReadonlyArray<readonly [string, number]>

export async function accountHeadWriter(masterKey: Uint8Array, deviceId: string): Promise<string> {
  return (await getCryptoWasm()).accountHeadWriter(toBase64(masterKey), deviceId)
}

export async function accountHeadScope(masterKey: Uint8Array, scope: string, index: HeadIndex): Promise<HeadScope> {
  return (await getCryptoWasm()).accountHeadScope(toBase64(masterKey), scope, JSON.stringify(index)) as HeadScope
}

/** The next head, sealed: after `previous` (null: the account's first), with `scopes` replaced. */
export async function nextAccountHead(
  masterKey: Uint8Array,
  binding: string,
  incarnationId: string,
  previous: string | null,
  writer: string,
  scopes: readonly HeadScope[],
): Promise<string> {
  return (await getCryptoWasm()).nextAccountHead(
    toBase64(masterKey),
    binding,
    incarnationId,
    previous ?? undefined,
    writer,
    JSON.stringify(scopes),
  )
}

export async function openAccountHead(masterKey: Uint8Array, binding: string, sealed: string): Promise<AccountHead> {
  return (await getCryptoWasm()).openAccountHead(toBase64(masterKey), binding, sealed) as AccountHead
}

export async function accountHeadAnchor(sealed: string): Promise<HeadAnchor> {
  return (await getCryptoWasm()).accountHeadAnchor(sealed) as HeadAnchor
}

/** See {@link HeadStatus}; `segment` is the chain from the anchor to `current`, or null when the server no longer keeps it. */
export async function checkAccountHead(
  masterKey: Uint8Array,
  binding: string,
  incarnationId: string,
  anchor: HeadAnchor | null,
  current: string,
  segment: readonly string[] | null,
): Promise<HeadStatus> {
  return (await getCryptoWasm()).checkAccountHead(
    toBase64(masterKey),
    binding,
    incarnationId,
    anchor ? JSON.stringify(anchor) : undefined,
    current,
    segment ? JSON.stringify(segment) : undefined,
  ) as HeadStatus
}

/** Whether a scope's index matches the verified head (false: the head does not cover it yet); throws if it differs. */
export async function checkAccountHeadIndex(
  masterKey: Uint8Array,
  binding: string,
  current: string,
  scope: string,
  index: HeadIndex,
): Promise<boolean> {
  return (await getCryptoWasm()).checkAccountHeadIndex(toBase64(masterKey), binding, current, scope, JSON.stringify(index))
}

/** Re-anchors on `current` after a check gave `status`; the record to log. */
export async function reanchorAccountHead(
  masterKey: Uint8Array,
  binding: string,
  incarnationId: string,
  anchor: HeadAnchor | null,
  current: string,
  status: HeadStatus,
): Promise<Reanchored> {
  return (await getCryptoWasm()).reanchorAccountHead(
    toBase64(masterKey),
    binding,
    incarnationId,
    anchor ? JSON.stringify(anchor) : undefined,
    current,
    JSON.stringify(status),
    Date.now(),
  ) as Reanchored
}
