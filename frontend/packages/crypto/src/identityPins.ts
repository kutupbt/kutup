// Drive identity (docs/plans/drive-identity-pins.md): an account's binding
// of its Drive keys to its authority, and the account's sealed list of pins
// on other accounts' authorities. Rust owns both formats
// (kutup-crypto drive_key_binding, identity_pins).

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
}

export interface IdentityPins {
  /** Sorted by account, one each. */
  pins: IdentityPin[]
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
 * Seals the pin list at `revision` (pins sorted by account), bound to the
 * account's key binding (`session.envelopeBinding`), never its address.
 */
export async function sealIdentityPins(masterKeyBase64: string, binding: string, revision: number, list: IdentityPins): Promise<string> {
  return (await getCryptoWasm()).sealIdentityPins(masterKeyBase64, binding, revision, JSON.stringify(list))
}

/** Opens the pin list of the account whose key binding is `binding`: the list and the revision it was sealed at. */
export async function openIdentityPins(masterKeyBase64: string, binding: string, sealed: string): Promise<{ list: IdentityPins; revision: number }> {
  const opened = (await getCryptoWasm()).openIdentityPins(masterKeyBase64, binding, sealed)
  return { list: JSON.parse(opened.value) as IdentityPins, revision: opened.revision }
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
