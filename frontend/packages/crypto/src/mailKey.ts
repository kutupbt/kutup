import { getCryptoWasm } from './rustWasm'

// Mail address keys (docs/plans/mail-address-keys.md): OpenPGP keys per
// address, generated and sealed in Rust (kutup-crypto `mail_key`); the secret
// key never reaches JavaScript unsealed.

/** Proton's key flags, the same bits. */
export const MAIL_KEY_FLAGS = {
  notCompromised: 1,
  notObsolete: 2,
  emailNoEncrypt: 4,
  emailNoSign: 8,
} as const
export const DEFAULT_MAIL_KEY_FLAGS = MAIL_KEY_FLAGS.notCompromised | MAIL_KEY_FLAGS.notObsolete

export interface GeneratedMailAddressKey {
  /** Binary OpenPGP public key, base64. */
  publicKey: string
  /** The secret key sealed under the master key, base64. */
  envelope: string
  fingerprint: string
  sha256Fingerprint: string
}

export interface MailKeyEntry {
  fingerprint: string
  sha256Fingerprint: string
  primary: boolean
  flags: number
}

export interface MailKeyListInput {
  account: string
  address: string
  sequence: number
  previousHash?: string
  issuedAt: string
  keys: MailKeyEntry[]
}

export interface SignedMailKeyList extends MailKeyListInput {
  data: string
  signature: string
  hash: string
}

export async function generateMailAddressKey(
  masterKeyBase64: string,
  loginEmail: string,
  address: string,
  createdAt: Date = new Date(),
): Promise<GeneratedMailAddressKey> {
  const seconds = Math.floor(createdAt.getTime() / 1000)
  return (await getCryptoWasm()).generateMailAddressKey(masterKeyBase64, loginEmail, address, seconds)
}

export async function inspectMailAddressPublicKey(
  publicKeyBase64: string,
  address: string,
): Promise<{ fingerprint: string; sha256Fingerprint: string; createdAt: number }> {
  return (await getCryptoWasm()).inspectMailAddressPublicKey(publicKeyBase64, address)
}

export async function armorMailPublicKey(publicKeyBase64: string): Promise<string> {
  return (await getCryptoWasm()).armorMailPublicKey(publicKeyBase64)
}

/** Signs a key list with the account authority derived from the master key. */
export async function signMailKeyList(masterKeyBase64: string, list: MailKeyListInput): Promise<SignedMailKeyList> {
  return (await getCryptoWasm()).signMailKeyList(masterKeyBase64, list)
}

/**
 * Verifies a key list against an account authority and, when given, that it
 * directly follows `previous`.
 */
export async function verifyMailKeyList(
  list: { data: string; signature: string },
  authorityPublicKeyBase64: string,
  previous?: { data: string; signature: string },
): Promise<SignedMailKeyList> {
  return (await getCryptoWasm()).verifyMailKeyList(
    list.data,
    list.signature,
    authorityPublicKeyBase64,
    previous?.data,
    previous?.signature,
  )
}
