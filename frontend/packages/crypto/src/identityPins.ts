// Drive identity (docs/plans/drive-identity-pins.md): an account's binding
// of its Drive keys to its authority, and the account's sealed list of pins
// on other accounts' authorities. Rust owns both formats
// (kutup-crypto drive_key_binding, identity_pins).

import type { AccountRenameV1 } from './accountRename'
import { getCryptoWasm } from './rustWasm'

/** One account's pinned authority. */
export interface IdentityPin {
  /** Canonical `username@server`. */
  account: string
  /** Canonical padded base64 Ed25519 key. */
  authorityPublicKey: string
  /** `seen`: trusted when first met (or accepted after a change); `verified`: compared in person. */
  state: 'seen' | 'verified'
  /** RFC 3339 UTC: first pinned, or last accepted. */
  since: string
  /** Incarnation ids the address had before, oldest first. */
  replaced?: string[]
  /** Addresses this same account had before `account` (its renames), oldest first. */
  formerly?: string[]
  /** The newest rename verified for it: a later chain must hold it (no rollback). */
  renames?: { sequence: number; digest: string; [later: string]: unknown }
  /** On a detached pin: why it left its address (`rename`: it comes back as it was; `replaced`: the user replaced it). */
  detachedBy?: 'rename' | 'replaced'
  /** Fields from a later version: kept and written back as they are. */
  [later: string]: unknown
}

export interface IdentityPins {
  /** Sorted by account, one each. */
  pins: IdentityPin[]
  /** Pins pushed off their address (a rename landed there, or another identity was accepted there): kept with their trust. */
  detached?: IdentityPin[]
  /** The lowest reader version that may read the list (absent: 1). */
  minReader?: number
  [later: string]: unknown
}

/** The account's Drive key binding, signed with its authority. */
export async function signDriveKeyBinding(masterKeyBase64: string, account: string): Promise<string> {
  return (await getCryptoWasm()).signDriveKeyBinding(masterKeyBase64, account)
}

/** Whether `authority` vouches for these Drive keys of `account`. */
export async function verifyDriveKeyBinding(
  account: string,
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
 * The safety number two accounts compare in person: the same in Chat, Drive
 * and the CLI. It binds their authority keys only, so a rename keeps it.
 */
export async function deriveSafetyNumber(
  localAuthority: string,
  peerAuthority: string,
): Promise<{ fingerprint: string; qrPayload: string }> {
  return (await getCryptoWasm()).deriveSafetyNumber(localAuthority, peerAuthority)
}

/** Whether a scanned safety QR is exactly the one for these two authorities (compared in Rust). */
export async function safetyQrMatches(localAuthority: string, peerAuthority: string, scanned: string): Promise<boolean> {
  return (await getCryptoWasm()).safetyQrMatches(localAuthority, peerAuthority, scanned)
}

/** What a client learned about an account (the rules every app shares, in Rust). */
export type PinUpdate = 'firstSeen' | 'accepted' | 'verified'

/**
 * Records `update` about `account` at `authority`: pinned on first use,
 * replaced only when accepted or verified, history kept for the same
 * authority. The list after, and whether it changed.
 */
export async function recordIdentityPin(
  pins: PinsText,
  account: string,
  authorityPublicKey: string,
  update: PinUpdate,
  since: string,
): Promise<{ pins: PinsText; changed: boolean; result: Recorded }> {
  const out = (await getCryptoWasm()).recordIdentityPin(pins.text, account, authorityPublicKey, update, since) as {
    pins: string
    changed: boolean
    result: Recorded
  }
  return { pins: pinsText(out.pins), changed: out.changed, result: out.result }
}

/** A pin that had an address before, and where it is now (`null`: detached, not known). */
export interface MovedPin {
  pin: IdentityPin
  now: string | null
}

/**
 * What `recordIdentityPin` decided:
 * - `pinned` / `unchanged`;
 * - `formerAddressTaken`: not pinned; someone the user knew had this address
 *   and is elsewhere now (`pins`): this is another person ("changed");
 * - `knownElsewhere`: not pinned again; the same account is pinned under
 *   another of its names (`pin`); follow its rename chain to move it;
 * - `replacedIdentity`: not pinned; an identity the user replaced (its trust
 *   revoked) turning up again: a change, accepted only explicitly.
 */
export type Recorded =
  | { kind: 'pinned' }
  | { kind: 'unchanged' }
  | { kind: 'formerAddressTaken'; pins: MovedPin[] }
  | { kind: 'knownElsewhere'; pin: IdentityPin }
  | { kind: 'replacedIdentity'; pin: IdentityPin }

/**
 * What the list says about `address`, given the authority published there
 * now (`null`: nobody, or not looked up):
 * - `pinned`: a pin for the address (`sameAuthority`: still that one);
 * - `renamed`: the authority there is pinned under another address: this
 *   account was renamed; fetch its chain and `applyAccountRenameToPins`;
 * - `returned`: a detached pin last known at this address is back
 *   (`recordIdentityPin` re-attaches it with its trust);
 * - `moved`: pinned accounts had the address before (`now`: where they are,
 *   or `null` if detached); whoever is there now is someone else;
 * - `replaced`: an identity the user replaced (its trust revoked), here or at
 *   another address;
 * - `new`: nothing known.
 */
export type PinMatch =
  | { kind: 'pinned'; pin: IdentityPin; sameAuthority: boolean }
  | { kind: 'renamed'; pin: IdentityPin }
  | { kind: 'returned'; pin: IdentityPin }
  | { kind: 'moved'; pins: MovedPin[] }
  | { kind: 'replaced'; pin: IdentityPin }
  | { kind: 'new' }

export async function lookupIdentityPin(pins: PinsText, address: string, publishedAuthority: string | null): Promise<PinMatch> {
  return (await getCryptoWasm()).lookupIdentityPin(pins.text, address, publishedAuthority ?? undefined) as PinMatch
}

/** What following a rename did. */
export interface RenameApplied {
  from: string
  to: string
  /** False: this chain was already applied. */
  changed: boolean
  /** The incarnation pinned at `to` before (its previous holder), now replaced. */
  displaced: string | null
}

/**
 * Follows a verified rename chain of the account whose authority is given:
 * its pin moves to the chain's current address with its trust and history.
 * Throws for a chain that does not verify, concerns no pinned account, or
 * rolls back the rename pinned.
 */
export async function applyAccountRenameToPins(
  pins: PinsText,
  authorityPublicKey: string,
  chain: readonly AccountRenameV1[],
): Promise<{ pins: PinsText; applied: RenameApplied }> {
  const result = (await getCryptoWasm()).applyAccountRenameToPins(pins.text, authorityPublicKey, JSON.stringify(chain))
  const { pins: text, ...applied } = result as RenameApplied & { pins: string }
  return { pins: pinsText(text), applied }
}
