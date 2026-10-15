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
  /** Addresses the account was met at, oldest first: labels, never keys. The last is the newest. */
  addresses?: string[]
  /** The newest rename verified for its authority: a later chain must hold it (no rollback). */
  renames?: { sequence: number; digest: string; [later: string]: unknown }
  /** Fields from a later version: kept and written back as they are. */
  [later: string]: unknown
}

export interface IdentityPins {
  /** Sorted by account, one each. */
  pins: IdentityPin[]
  /** The lowest reader version that may read the list (absent: 1). */
  minReader?: number
  [later: string]: unknown
}

/** The newest address a pin was met at. */
export function pinAddress(pin: IdentityPin): string | undefined {
  return pin.addresses?.at(-1)
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
 * Records `update` about `account`, met at `address` (null when it came
 * without one) with `authority`: pinned on first use, replaced only when
 * accepted or verified. The list after, and whether it changed.
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
 * - `addressHadOthers`: not pinned; accounts the user knew were met at this
 *   address (`pins`), and this is someone else; pinned only when accepted;
 * - `authorityElsewhere`: refused; this authority is pinned for another
 *   account (`pin`): someone else's keys handed out under this account.
 */
export type Recorded =
  | { kind: 'updated' }
  | { kind: 'unchanged' }
  | { kind: 'addressHadOthers'; pins: IdentityPin[] }
  | { kind: 'authorityElsewhere'; pin: IdentityPin }

/**
 * What the list says about `account`, met at `address` (null: it came
 * without one, as an inbound message does), given the authority published
 * for it now (null: not looked up):
 * - `pinned`: `sameAuthority` false is "safety number changed";
 *   `earlierAuthority`: the published key is one this account had before;
 * - `someoneElse`: not pinned, but accounts the list knows were met at the
 *   address (`pins`, newest holder first): whoever has it now is another person;
 * - `new`: nothing known.
 */
export type PinMatch =
  | { kind: 'pinned'; pin: IdentityPin; sameAuthority: boolean; earlierAuthority: boolean }
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

/** Every pin met at `address`, newest holder first (compared folded, in Rust). */
export async function identityPinsAt(pins: PinsText, address: string): Promise<IdentityPin[]> {
  return (await getCryptoWasm()).identityPinsAt(pins.text, address) as IdentityPin[]
}

/** What following a rename did. */
export interface RenameApplied {
  /** The pin's newest address before. */
  from: string | null
  /** The chain's current address, now the newest. */
  to: string
  /** False: this chain was already applied. */
  changed: boolean
}

/**
 * Follows a verified rename chain of `account`, signed by its pinned
 * authority: the chain's addresses become the pin's labels. Trust is
 * untouched. Throws for a chain that does not verify against the pinned
 * authority, an account not pinned, or a rollback.
 */
export async function applyAccountRenameToPins(
  pins: PinsText,
  account: AccountRef,
  chain: readonly AccountRenameV1[],
): Promise<{ pins: PinsText; applied: RenameApplied }> {
  const result = (await getCryptoWasm()).applyAccountRenameToPins(pins.text, account, JSON.stringify(chain))
  const { pins: text, ...applied } = result as RenameApplied & { pins: string }
  return { pins: pinsText(text), applied }
}
