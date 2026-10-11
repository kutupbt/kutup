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

/** Shortest passphrase an exported key may be locked with (kutup-crypto `MIN_EXPORT_PASSPHRASE_CHARS`). */
export const MIN_MAIL_KEY_PASSPHRASE = 8

/** An address key as an armored OpenPGP secret key file locked with `passphrase`. */
export async function exportMailAddressKey(key: SealedMailKey, passphrase: string): Promise<string> {
  return (await getCryptoWasm()).exportMailAddressKey(key.masterKeyBase64, key.loginEmail, key.address, key.envelope, key.fingerprint, passphrase)
}

/** The passphrase does not open the key file. */
export class WrongKeyPassphrase extends Error {
  constructor() {
    super('wrong passphrase')
  }
}

/**
 * Reads an address key from an OpenPGP secret key file (Kutup's export,
 * Proton's or GnuPG's) for `address`, sealed under the master key.
 */
export async function importMailAddressKey(
  masterKeyBase64: string,
  loginEmail: string,
  address: string,
  file: Uint8Array,
  passphrase: string,
): Promise<GeneratedMailAddressKey> {
  try {
    return (await getCryptoWasm()).importMailAddressKey(masterKeyBase64, loginEmail, address, file, passphrase)
  } catch (error) {
    // WASM throws its messages as strings.
    if (error === 'wrong passphrase' || (error instanceof Error && error.message === 'wrong passphrase')) throw new WrongKeyPassphrase()
    throw error
  }
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

/** An address key as its owner holds it: sealed, opened only inside WASM. */
export interface SealedMailKey {
  masterKeyBase64: string
  loginEmail: string
  address: string
  envelope: string
  fingerprint: string
}

export interface OpenedMail {
  /** The message as sent: RFC 5322 bytes. */
  data: Uint8Array
  /** Whether it carried an OpenPGP signature. */
  signed: boolean
  /** Whether that signature is valid for the sender key given. */
  verified: boolean
}

/**
 * Opens a stored message (docs/plans/mail.md) with the address key; with
 * `senderPublicKey` (base64), checks its signature too.
 */
export async function openMailMessage(key: SealedMailKey, message: Uint8Array, senderPublicKey?: string): Promise<OpenedMail> {
  const opened = (await getCryptoWasm()).openMailMessage(
    key.masterKeyBase64,
    key.loginEmail,
    key.address,
    key.envelope,
    key.fingerprint,
    message,
    senderPublicKey,
  )
  try {
    return { data: opened.data, signed: opened.signed, verified: opened.verified }
  } finally {
    opened.free()
  }
}

export interface SealedMail {
  /** One base64 key packet per recipient key, in the order given. */
  keyPackets: string[]
  dataPacket: Uint8Array
}

/**
 * Encrypts `plaintext` once to every key (base64; include your own for your
 * copy) and signs it with the address key, split the way the server stores
 * mail between Kutup users.
 */
export async function encryptMailMessage(key: SealedMailKey, recipientPublicKeys: string[], plaintext: Uint8Array): Promise<SealedMail> {
  const sealed = (await getCryptoWasm()).encryptMailMessage(
    key.masterKeyBase64,
    key.loginEmail,
    key.address,
    key.envelope,
    key.fingerprint,
    recipientPublicKeys,
    plaintext,
  )
  try {
    return { keyPackets: sealed.keyPackets, dataPacket: sealed.dataPacket }
  } finally {
    sealed.free()
  }
}

/** An outside correspondent's key, checked (docs/plans/mail.md, C3). */
export interface ExternalMailKey {
  /** Binary, base64. */
  publicKey: string
  fingerprint: string
  createdAt: number
}

/**
 * Checks an outside key for `address`: self-signed, not revoked or expired,
 * a user ID for the address and an encryption subkey. Armored or binary.
 */
export async function inspectExternalMailKey(publicKey: Uint8Array, address: string): Promise<ExternalMailKey> {
  return (await getCryptoWasm()).inspectExternalMailKey(publicKey, address)
}

/** An outside key as it is, unchecked: for showing a pinned key, even an expired one. */
export async function describeExternalMailKey(publicKey: Uint8Array): Promise<ExternalMailKey> {
  return (await getCryptoWasm()).describeExternalMailKey(publicKey)
}

/**
 * Encrypts to outside keys and the sender's own (base64), signed inside:
 * the armored message for a PGP/MIME `multipart/encrypted` part.
 */
export async function encryptMailPgp(key: SealedMailKey, recipientPublicKeys: string[], plaintext: Uint8Array): Promise<string> {
  return (await getCryptoWasm()).encryptMailPgp(
    key.masterKeyBase64,
    key.loginEmail,
    key.address,
    key.envelope,
    key.fingerprint,
    recipientPublicKeys,
    plaintext,
  )
}

/** Whether a `multipart/signed` signature signs `content` with the key (base64). */
export async function verifyMailDetachedSignature(signature: Uint8Array, content: Uint8Array, signerPublicKey: string): Promise<boolean> {
  return (await getCryptoWasm()).verifyMailDetachedSignature(signature, content, signerPublicKey)
}

/** A cleartext-signed message's text, and whether it verifies against the key when given. */
export async function verifyMailCleartext(message: string, signerPublicKey?: string): Promise<{ text: string; verified: boolean }> {
  return (await getCryptoWasm()).verifyMailCleartext(message, signerPublicKey)
}

// --- Shared mailboxes (docs/plans/mail-groups.md, G1b) ---------------------

/** A shared mailbox's key as a member holds it: their share, opened only inside WASM with their own address key. */
export interface GroupMailKey {
  /** The member's own address key, which opens the share. */
  member: SealedMailKey
  /** The group key's secret, encrypted to the member's address key (base64). */
  share: string
  /** The group key's fingerprint. */
  fingerprint: string
}

export interface GeneratedMailGroupKey {
  publicKey: string
  fingerprint: string
  sha256Fingerprint: string
  /** One per member public key, in the order given. */
  shares: string[]
}

/** Makes a shared mailbox's key, with a share for each member's address key (base64). */
export async function generateMailGroupKey(groupAddress: string, memberPublicKeys: string[], createdAt: Date = new Date()): Promise<GeneratedMailGroupKey> {
  return (await getCryptoWasm()).generateMailGroupKey(groupAddress, Math.floor(createdAt.getTime() / 1000), memberPublicKeys)
}

/** Shares a group key the caller holds with more members, one share per public key. */
export async function reshareMailGroupKey(key: GroupMailKey, memberPublicKeys: string[]): Promise<string[]> {
  const m = key.member
  return (await getCryptoWasm()).reshareMailGroupKey(m.masterKeyBase64, m.loginEmail, m.address, m.envelope, m.fingerprint, key.share, key.fingerprint, memberPublicKeys)
}

/** Opens a shared mailbox's message with its group key; with `senderPublicKey`, checks the signature too. */
export async function openMailGroupMessage(key: GroupMailKey, message: Uint8Array, senderPublicKey?: string): Promise<OpenedMail> {
  const m = key.member
  const opened = (await getCryptoWasm()).openMailGroupMessage(
    m.masterKeyBase64,
    m.loginEmail,
    m.address,
    m.envelope,
    m.fingerprint,
    key.share,
    key.fingerprint,
    message,
    senderPublicKey,
  )
  try {
    return { data: opened.data, signed: opened.signed, verified: opened.verified }
  } finally {
    opened.free()
  }
}

/** `encryptMailMessage` signed by the group key: a member writing as the shared mailbox. */
export async function encryptMailMessageAsGroup(key: GroupMailKey, recipientPublicKeys: string[], plaintext: Uint8Array): Promise<SealedMail> {
  const m = key.member
  const sealed = (await getCryptoWasm()).encryptMailMessageAsGroup(
    m.masterKeyBase64,
    m.loginEmail,
    m.address,
    m.envelope,
    m.fingerprint,
    key.share,
    key.fingerprint,
    recipientPublicKeys,
    plaintext,
  )
  try {
    return { keyPackets: sealed.keyPackets, dataPacket: sealed.dataPacket }
  } finally {
    sealed.free()
  }
}

/** `encryptMailPgp` signed by the group key. */
export async function encryptMailPgpAsGroup(key: GroupMailKey, recipientPublicKeys: string[], plaintext: Uint8Array): Promise<string> {
  const m = key.member
  return (await getCryptoWasm()).encryptMailPgpAsGroup(
    m.masterKeyBase64,
    m.loginEmail,
    m.address,
    m.envelope,
    m.fingerprint,
    key.share,
    key.fingerprint,
    recipientPublicKeys,
    plaintext,
  )
}
