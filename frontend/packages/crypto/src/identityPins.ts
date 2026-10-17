// Drive identity (docs/plans/drive-identity-pins.md): an account's binding
// of its Drive keys to its authority, and the account's sealed list of pins
// on other accounts' authorities. Rust owns both formats
// (kutup-crypto drive_key_binding, identity_pins).

import type { AccountRef } from './accountRef'
import type { AccountRenameV1 } from './accountRename'
import { getCryptoWasm } from './rustWasm'

/** One account's pinned authority. */
export interface IdentityPin {
  /** Who: the pin's key, permanent. */
  account: AccountRef
  /** Canonical padded base64 Ed25519 key. */
  authorityPublicKey: string
  /** `seen`: trusted when first met (or accepted after a change); `verified`: compared in person. */
  state: 'seen' | 'verified'
  /** RFC 3339 UTC: first pinned, or last accepted. */
  since: string
  /** Incarnation ids this account had before (changes accepted), oldest first. */
  replaced?: string[]
  /**
   * Addresses the account is known at, oldest first: labels, never keys. Only
   * the one it was first met at and those its own signed rename chain proves;
   * never one a server resolved to it. The last is the one it holds now.
   */
  addresses?: AddressLabel[]
  /** The newest rename verified for its authority: a later chain must hold it (no rollback). */
  renames?: { sequence: number; digest: string; [later: string]: unknown }
  /** Fields from a later version: kept and written back as they are. */
  [later: string]: unknown
}

/** An address a pinned account is known at, and when the list learned it. */
export interface AddressLabel {
  address: string
  /** RFC 3339 UTC. */
  seenAt: string
  [later: string]: unknown
}

/**
 * One shared mailbox's key-list signer (Rust `GroupPinV1`): its own group
 * signing key, which its managers hold, pinned by the mailbox's permanent id.
 */
export interface GroupPin {
  server: string
  groupId: string
  /** Canonical padded base64 Ed25519 key. */
  signerPublicKey: string
  since: string
  /** The newest list seen: a later chain must hold it at `sequence`. */
  anchor: { sequence: number; digest: string; [later: string]: unknown }
  replaced?: string[]
  [later: string]: unknown
}

export interface IdentityPins {
  /** Sorted by account, one each. */
  pins: IdentityPin[]
  /** Shared mailboxes, sorted by server and group id. */
  groups?: GroupPin[]
  /** The lowest reader version that may read the list (absent: 1). */
  minReader?: number
  [later: string]: unknown
}

/** The address a pinned account holds now, as far as the list knows: its own name. */
export function pinAddress(pin: IdentityPin): string | undefined {
  return pin.addresses?.at(-1)?.address
}

/** The account's Drive key binding, signed with its authority for `account` (its server and id). */
export async function signDriveKeyBinding(masterKeyBase64: string, account: AccountRef): Promise<string> {
  return (await getCryptoWasm()).signDriveKeyBinding(masterKeyBase64, account)
}

/** Whether `authority` vouches for these Drive keys of `account`. */
export async function verifyDriveKeyBinding(
  account: AccountRef,
  authorityPublicKey: string,
  driveHpkePublicKey: string,
  driveSigningPublicKey: string,
  binding: string,
): Promise<boolean> {
  return (await getCryptoWasm()).verifyDriveKeyBinding(account, authorityPublicKey, driveHpkePublicKey, driveSigningPublicKey, binding)
}

/** The incarnation id an authority key stands for. */
export async function incarnationIdOfAuthority(authorityPublicKey: string): Promise<string> {
  return (await getCryptoWasm()).incarnationIdOfAuthority(authorityPublicKey)
}

/**
 * The pin list as JavaScript holds it: `text` is the list's canonical JSON,
 * exactly as Rust wrote it, and the only form passed back to Rust; `list` is
 * a read-only view of it. JavaScript never re-serializes the list, so fields
 * from a later version (numbers included) reach the next seal untouched.
 */
export interface PinsText {
  text: string
  list: IdentityPins
}

function pinsText(text: string): PinsText {
  return { text, list: JSON.parse(text) as IdentityPins }
}

/** An empty list. */
export const EMPTY_PINS: PinsText = pinsText('{"pins":[]}')

/**
 * Seals the pin list at `revision`, bound to the account's key binding
 * (`session.envelopeBinding`), never its address.
 */
export async function sealIdentityPins(masterKeyBase64: string, binding: string, revision: number, pins: PinsText): Promise<string> {
  return (await getCryptoWasm()).sealIdentityPins(masterKeyBase64, binding, revision, pins.text)
}

/** Opens the pin list of the account whose key binding is `binding`, and the revision it was sealed at. */
export async function openIdentityPins(masterKeyBase64: string, binding: string, sealed: string): Promise<{ pins: PinsText; revision: number }> {
  const opened = (await getCryptoWasm()).openIdentityPins(masterKeyBase64, binding, sealed)
  return { pins: pinsText(opened.value), revision: opened.revision }
}

/**
 * The safety number this account (`local`) and `peer` compare in person: the
 * same in Chat, Drive and the CLI. Signal's fingerprint over each account
 * and its authority key, so a rename keeps it and a reset changes it.
 */
export async function deriveSafetyNumber(
  local: AccountRef,
  localAuthority: string,
  peer: AccountRef,
  peerAuthority: string,
): Promise<{ fingerprint: string; qrPayload: string }> {
  return (await getCryptoWasm()).deriveSafetyNumber(local, localAuthority, peer, peerAuthority)
}

/** Whether a scanned safety QR is the peer's own code for exactly this pair (compared in Rust). */
export async function safetyQrMatches(
  local: AccountRef,
  localAuthority: string,
  peer: AccountRef,
  peerAuthority: string,
  scanned: string,
): Promise<boolean> {
  return (await getCryptoWasm()).safetyQrMatches(local, localAuthority, peer, peerAuthority, scanned)
}

/** What a client learned about an account (the rules every app shares, in Rust). */
export type PinUpdate = 'firstSeen' | 'accepted' | 'verified'

/**
 * Records `update` about `account`, found at `address` (null when it came
 * without one) with `authority`: pinned on first use (the address kept as the
 * one it was first met at) unless others were known there, replaced only
 * when accepted or verified. An address is never written onto an account
 * already pinned. The list after, and whether it changed.
 */
export async function recordIdentityPin(
  pins: PinsText,
  account: AccountRef,
  address: string | null,
  authorityPublicKey: string,
  update: PinUpdate,
  since: string,
): Promise<{ pins: PinsText; changed: boolean; result: Recorded }> {
  const out = (await getCryptoWasm()).recordIdentityPin(pins.text, account, address ?? undefined, authorityPublicKey, update, since) as {
    pins: string
    changed: boolean
    result: Recorded
  }
  return { pins: pinsText(out.pins), changed: out.changed, result: out.result }
}

/**
 * What `recordIdentityPin` decided:
 * - `updated` / `unchanged` (for `firstSeen`, also another authority than
 *   the pinned one: `lookupIdentityPin` reports it as changed);
 * - `addressHadOthers`: not pinned; the account is new and the list knew
 *   others at this address (`pins`): someone else, pinned only when accepted;
 * - `addressHeldByOthers`: refused; the account is pinned and was reached by
 *   an address another pinned account holds (`pins`): a key change is
 *   accepted only for the account opened by its own name;
 * - `authorityElsewhere`: refused; this authority is pinned for another
 *   account (`pin`): someone else's keys handed out under this account.
 */
export type Recorded =
  | { kind: 'updated' }
  | { kind: 'unchanged' }
  | { kind: 'addressHadOthers'; pins: IdentityPin[] }
  | { kind: 'addressHeldByOthers'; pins: IdentityPin[] }
  | { kind: 'authorityElsewhere'; pin: IdentityPin }

/**
 * How the published authority compares with the pinned one: `same`;
 * `changed` (the safety number changed); `earlier` (one the account had
 * before, handed out again: a change too); `unknown` (not looked up: neither).
 */
export type AuthorityCheck = 'same' | 'changed' | 'earlier' | 'unknown'

/**
 * What the list says about `account`, found at `address` (null: it came
 * without one, as an inbound message does), given the authority published
 * for it now (null: not looked up). As Signal, an address only finds an
 * account; the account is shown by its own name (`pinAddress(pin)`), never
 * by the address it was found at:
 * - `pinned`: `others` are accounts the list knows hold the address now:
 *   the address is someone else's ("someone else" notice), checked before
 *   `authority`; `knownAt`: the address is one of its own labels (folded);
 * - `someoneElse`: the account is new, but the list knew others at the
 *   address (`pins`, those that hold it now first);
 * - `new`: nothing known.
 */
export type PinMatch =
  | { kind: 'pinned'; pin: IdentityPin; authority: AuthorityCheck; others: IdentityPin[]; knownAt: boolean }
  | { kind: 'someoneElse'; pins: IdentityPin[] }
  | { kind: 'new' }

export async function lookupIdentityPin(
  pins: PinsText,
  account: AccountRef,
  address: string | null,
  publishedAuthority: string | null,
): Promise<PinMatch> {
  return (await getCryptoWasm()).lookupIdentityPin(pins.text, account, address ?? undefined, publishedAuthority ?? undefined) as PinMatch
}

/** Every pin known at `address`: those that hold it now first, by when it was seen (compared folded, in Rust). */
export async function identityPinsAt(pins: PinsText, address: string): Promise<IdentityPin[]> {
  return (await getCryptoWasm()).identityPinsAt(pins.text, address) as IdentityPin[]
}

/** What following a rename did. */
export interface RenameApplied {
  /** The address the pin held before. */
  from: string | null
  /** The chain's current address, which the pin holds now. */
  to: string
  /** False: this chain was already applied. */
  changed: boolean
}

/**
 * Follows a verified rename chain of `account`, signed by its pinned
 * authority, at `since`: the chain's addresses become the pin's labels (the
 * only way an address joins a known account). Trust is untouched. Throws for
 * a chain that does not verify against the pinned authority, an account not
 * pinned, or a rollback.
 */
export async function applyAccountRenameToPins(
  pins: PinsText,
  account: AccountRef,
  chain: readonly AccountRenameV1[],
  since: string,
): Promise<{ pins: PinsText; applied: RenameApplied }> {
  const result = (await getCryptoWasm()).applyAccountRenameToPins(pins.text, account, JSON.stringify(chain), since)
  const { pins: text, ...applied } = result as RenameApplied & { pins: string }
  return { pins: pinsText(text), applied }
}

/** A shared mailbox's verified key-list chain: its signers (base64, oldest first) and list digests (hex, list 1 first). */
export interface GroupChain {
  signers: readonly string[]
  digests: readonly string[]
}

/**
 * What the list says about a shared mailbox's chain: `new` (trusted on first
 * use), `same` (it continues the pin: the pinned signer in its line, the
 * anchored list in place), or `changed` (another signer, a restarted chain, a
 * rollback, a fork): warned about until the user accepts it.
 */
export type GroupMatch = { kind: 'new' } | { kind: 'same'; pin: GroupPin } | { kind: 'changed'; pin: GroupPin }

export async function lookupGroupPin(pins: PinsText, server: string, groupId: string, chain: GroupChain): Promise<GroupMatch> {
  return (await getCryptoWasm()).lookupGroupPin(pins.text, server, groupId, [...chain.signers], [...chain.digests]) as GroupMatch
}

/** Records what a sender learned about a shared mailbox: met (`firstSeen`), or a change the user `accepted`. */
export async function recordGroupPin(
  pins: PinsText,
  server: string,
  groupId: string,
  chain: GroupChain,
  update: 'firstSeen' | 'accepted',
  since: string,
): Promise<{ pins: PinsText; changed: boolean }> {
  const out = (await getCryptoWasm()).recordGroupPin(pins.text, server, groupId, [...chain.signers], [...chain.digests], update, since) as {
    pins: string
    changed: boolean
  }
  return { pins: pinsText(out.pins), changed: out.changed }
}
