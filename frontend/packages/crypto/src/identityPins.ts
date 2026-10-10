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

/** Seals the pin list of `owner` at `revision` (pins sorted by account). */
export async function sealIdentityPins(masterKeyBase64: string, owner: string, revision: number, list: IdentityPins): Promise<string> {
  return (await getCryptoWasm()).sealIdentityPins(masterKeyBase64, owner, revision, JSON.stringify(list))
}

/** Opens the pin list of `owner` stored at `revision`. */
export async function openIdentityPins(masterKeyBase64: string, owner: string, revision: number, sealed: string): Promise<IdentityPins> {
  return JSON.parse((await getCryptoWasm()).openIdentityPins(masterKeyBase64, owner, revision, sealed)) as IdentityPins
}
