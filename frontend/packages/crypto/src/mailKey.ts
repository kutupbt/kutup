import type { AccountRef } from './accountRef'
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
  binding: string,
  address: string,
  createdAt: Date = new Date(),
): Promise<GeneratedMailAddressKey> {
  const seconds = Math.floor(createdAt.getTime() / 1000)
  return (await getCryptoWasm()).generateMailAddressKey(masterKeyBase64, binding, address, seconds)
}

/** Shortest passphrase an exported key may be locked with (kutup-crypto `MIN_EXPORT_PASSPHRASE_CHARS`). */
export const MIN_MAIL_KEY_PASSPHRASE = 8

/** An address key as an armored OpenPGP secret key file locked with `passphrase`. */
export async function exportMailAddressKey(key: SealedMailKey, passphrase: string): Promise<string> {
  return (await getCryptoWasm()).exportMailAddressKey(key.masterKeyBase64, key.binding, key.address, key.envelope, key.fingerprint, passphrase)
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
  binding: string,
  address: string,
  file: Uint8Array,
  passphrase: string,
): Promise<GeneratedMailAddressKey> {
  try {
    return (await getCryptoWasm()).importMailAddressKey(masterKeyBase64, binding, address, file, passphrase)
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
 * An address folded as Kutup servers compare names (`.`, `_`, `-` and case
 * ignored in the local part; one account per folded name), or null. Rust's
 * `kutup_crypto::names::fold_address`.
 */
export async function foldAddress(address: string): Promise<string | null> {
  const at = address.lastIndexOf('@')
  if (at <= 0 || at === address.length - 1) return null
  const local = (await getCryptoWasm()).foldName(address.slice(0, at))
  return local ? `${local}@${address.slice(at + 1).toLowerCase()}` : null
}

/**
 * Verifies a key list against an account authority and, when given, that it
 * directly follows `previous`.
 */
/** A shared mailbox's verified key-list chain (Rust `mail_group::verify_group_key_chain`). */
export interface GroupKeyChainView {
  /** The first list's signer: what a sender pins on first sight (base64). */
  firstSigner: string
  /** The signer of the newest list, and every signer in order (base64). */
  signer: string
  signers: string[]
  sequence: number
  /** Each list's hash (hex), list 1's first. */
  digests: string[]
  newest: SignedMailKeyList
}

/** Checks a shared mailbox's whole key-list chain: signed by its signers in order, handed over only by the signer in force. */
export async function verifyMailGroupKeyChain(
  groupId: string,
  firstSigner: string,
  lists: { data: string; signature: string }[],
  handovers: string[],
): Promise<GroupKeyChainView> {
  const view = (await getCryptoWasm()).verifyMailGroupKeyChain(groupId, firstSigner, lists, handovers)
  return { ...view, newest: view.newest as SignedMailKeyList }
}

/** A shared mailbox's signing key as an owner or manager holds it; its seed is opened only inside WASM. */
export interface GroupSignerHolder {
  account: AccountRef
  hpkePrivateKey: string
  groupId: string
  /** The signer in force (base64) and the holder's share of its seed. */
  signer: string
  signingShare: string
}

function signerHolder(holder: GroupSignerHolder) {
  return {
    account: { server: holder.account.server, accountId: holder.account.accountId },
    hpkePrivateKey: holder.hpkePrivateKey,
    groupId: holder.groupId,
    signer: holder.signer,
    signingShare: holder.signingShare,
  }
}

/** Signs a shared mailbox's next key list with its signer in force. */
export async function signMailGroupKeyList(holder: GroupSignerHolder, list: MailKeyListInput): Promise<SignedMailKeyList> {
  return (await getCryptoWasm()).signMailGroupKeyList(signerHolder(holder), list) as SignedMailKeyList
}

/** A new signer for the shared mailbox: shared to `members` (its owners and managers), signing `list`, handed over from `outgoing` when there is one. */
export async function newMailGroupSigner(
  groupId: string,
  members: GroupKeyMember[],
  list: MailKeyListInput,
  outgoing?: { holder: GroupSignerHolder; previousListHash: string },
): Promise<{ publicKey: string; shares: string[]; keyList: SignedMailKeyList; handover?: string }> {
  const made = (await getCryptoWasm()).newMailGroupSigner(
    groupId,
    memberInputs(members),
    list,
    outgoing ? signerHolder(outgoing.holder) : undefined,
    outgoing?.previousListHash,
  )
  return { ...made, keyList: made.keyList as SignedMailKeyList }
}

/** The signer in force's seed shared with more owners and managers. */
export async function reshareMailGroupSigner(holder: GroupSignerHolder, members: GroupKeyMember[]): Promise<string[]> {
  return (await getCryptoWasm()).reshareMailGroupSigner(signerHolder(holder), memberInputs(members))
}

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
  binding: string
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
    key.binding,
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

/**
 * Opens a message forwarded to the address (its row's `forwardedFrom` is set)
 * with one of the address's forwarding keys (docs/plans/mail-forwarding.md):
 * no other key opens one, and a forwarding key opens nothing else.
 */
export async function openForwardedMailMessage(key: SealedMailKey, message: Uint8Array, senderPublicKey?: string): Promise<OpenedMail> {
  const opened = (await getCryptoWasm()).openForwardedMailMessage(
    key.masterKeyBase64,
    key.binding,
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

/** An end-to-end forwarding's material, the body of `POST /api/mail/forwardings`' `endToEnd`. */
export interface MailForwardingMaterial {
  /** The forwardee key's public part (base64). */
  forwardeePublicKey: string
  instances: { forwarderFingerprint: string; forwardeeFingerprint: string; proxyParameter: string }[]
  /** The forwardee key, sealed to the forwardee and signed by the forwarder (armored). */
  activation: string
}

/**
 * The material for an end-to-end forwarding from the forwarder's primary key
 * `key` to `forwardee` (whose primary public key, base64, comes from their
 * verified key list), bound to `forwardingId` (a UUID v4 the client chose)
 * and expiring at `expiresAt`. The forwarder's key never leaves WASM.
 */
export async function makeMailForwarding(
  key: SealedMailKey,
  forwardee: { address: string; publicKey: string },
  forwardingId: string,
  createdAt: Date,
  expiresAt: Date,
): Promise<MailForwardingMaterial> {
  return (await getCryptoWasm()).makeMailForwarding(
    key.masterKeyBase64,
    key.binding,
    key.address,
    key.envelope,
    key.fingerprint,
    forwardee.address,
    forwardee.publicKey,
    forwardingId,
    Math.floor(createdAt.getTime() / 1000),
    Math.floor(expiresAt.getTime() / 1000),
  )
}

/** The forwarding key as `POST /api/mail/forwardings/{id}/accept` takes it. */
export interface AcceptedMailForwarding {
  publicKey: string
  privateKeyEnvelope: string
  fingerprint: string
}

/**
 * The forwardee's accept: opens `activation` with their address key `key`,
 * checks it is signed by the forwarder's key (base64, from their verified
 * key list), for this forwarding and these addresses, and unexpired; returns
 * the forwarding key sealed like the address's other keys.
 */
export async function acceptMailForwarding(
  key: SealedMailKey,
  forwarder: { address: string; publicKey: string },
  forwardingId: string,
  activation: string,
): Promise<AcceptedMailForwarding> {
  return (await getCryptoWasm()).acceptMailForwarding(
    key.masterKeyBase64,
    key.binding,
    key.address,
    key.envelope,
    key.fingerprint,
    forwarder.address,
    forwarder.publicKey,
    forwardingId,
    Date.now() / 1000,
    activation,
  )
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
    key.binding,
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

/** An outside key as a contact's key table lists it (Proton's ContactKeysTable). */
export interface ExternalMailKeyDetails extends ExternalMailKey {
  /** Seconds since the epoch, when it stops being valid; none when it does not expire. */
  expiresAt?: number | null
  /** "RSA (4096)", "ECC (Curve25519)". */
  algorithm: string
  state: 'usable' | 'expired' | 'revoked' | 'otherAddress' | 'cannotEncrypt'
}

/** {@link describeExternalMailKey} with type, expiry and where the key stands for `address` now. */
export async function describeExternalMailKeyDetails(publicKey: Uint8Array, address: string): Promise<ExternalMailKeyDetails> {
  return (await getCryptoWasm()).describeExternalMailKeyDetails(publicKey, address)
}

/**
 * Encrypts to outside keys and the sender's own (base64), signed inside:
 * the armored message for a PGP/MIME `multipart/encrypted` part.
 */
export async function encryptMailPgp(key: SealedMailKey, recipientPublicKeys: string[], plaintext: Uint8Array): Promise<string> {
  return (await getCryptoWasm()).encryptMailPgp(
    key.masterKeyBase64,
    key.binding,
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

/**
 * A shared mailbox's key as a member holds it: their share, sealed to their
 * account key (docs/plans/account-ids.md) and opened only inside WASM.
 */
export interface GroupMailKey {
  /** The member: their account, whose Drive HPKE private key (base64) opens the share. */
  account: AccountRef
  hpkePrivateKey: string
  /** The group key's secret, sealed to the member's account key (base64). */
  share: string
  groupId: string
  /** The group key's fingerprint. */
  fingerprint: string
}

/** A member to share a group key with: their account and the account key their Drive key binding vouches for. */
export interface GroupKeyMember {
  account: AccountRef
  incarnationId: string
  hpkePublicKey: string
}

export interface GeneratedMailGroupKey {
  publicKey: string
  fingerprint: string
  sha256Fingerprint: string
  /** One per member, in the order given. */
  shares: string[]
}

function holder(key: GroupMailKey) {
  return {
    account: { server: key.account.server, accountId: key.account.accountId },
    hpkePrivateKey: key.hpkePrivateKey,
    share: key.share,
    groupId: key.groupId,
    fingerprint: key.fingerprint,
  }
}

function memberInputs(members: GroupKeyMember[]) {
  return members.map((m) => ({ account: { server: m.account.server, accountId: m.account.accountId }, incarnationId: m.incarnationId, hpkePublicKey: m.hpkePublicKey }))
}

/** Makes the shared mailbox `groupId`'s key, with a share for each member. */
export async function generateMailGroupKey(
  groupAddress: string,
  groupId: string,
  members: GroupKeyMember[],
  createdAt: Date = new Date(),
): Promise<GeneratedMailGroupKey> {
  return (await getCryptoWasm()).generateMailGroupKey(groupAddress, groupId, Math.floor(createdAt.getTime() / 1000), memberInputs(members))
}

/** Shares a group key the caller holds with more members, one share each. */
export async function reshareMailGroupKey(key: GroupMailKey, members: GroupKeyMember[]): Promise<string[]> {
  return (await getCryptoWasm()).reshareMailGroupKey(holder(key), memberInputs(members))
}

/** Opens a shared mailbox's message with its group key; with `senderPublicKey`, checks the signature too. */
export async function openMailGroupMessage(key: GroupMailKey, message: Uint8Array, senderPublicKey?: string): Promise<OpenedMail> {
  const opened = (await getCryptoWasm()).openMailGroupMessage(holder(key), message, senderPublicKey)
  try {
    return { data: opened.data, signed: opened.signed, verified: opened.verified }
  } finally {
    opened.free()
  }
}

/** `encryptMailMessage` signed by the group key: a member writing as the shared mailbox. */
export async function encryptMailMessageAsGroup(key: GroupMailKey, recipientPublicKeys: string[], plaintext: Uint8Array): Promise<SealedMail> {
  const sealed = (await getCryptoWasm()).encryptMailMessageAsGroup(holder(key), recipientPublicKeys, plaintext)
  try {
    return { keyPackets: sealed.keyPackets, dataPacket: sealed.dataPacket }
  } finally {
    sealed.free()
  }
}

/** `encryptMailPgp` signed by the group key. */
export async function encryptMailPgpAsGroup(key: GroupMailKey, recipientPublicKeys: string[], plaintext: Uint8Array): Promise<string> {
  return (await getCryptoWasm()).encryptMailPgpAsGroup(holder(key), recipientPublicKeys, plaintext)
}

// --- Encrypt and Sign per message (docs/plans/mail-encrypt-sign.md) --------

/** {@link encryptMailMessage} without a signature: the sender turned Sign off. */
export async function encryptMailMessageUnsigned(recipientPublicKeys: string[], plaintext: Uint8Array): Promise<SealedMail> {
  const sealed = (await getCryptoWasm()).encryptMailMessageUnsigned(recipientPublicKeys, plaintext)
  try {
    return { keyPackets: sealed.keyPackets, dataPacket: sealed.dataPacket }
  } finally {
    sealed.free()
  }
}

/** {@link encryptMailPgp} without a signature. */
export async function encryptMailPgpUnsigned(recipientPublicKeys: string[], plaintext: Uint8Array): Promise<string> {
  return (await getCryptoWasm()).encryptMailPgpUnsigned(recipientPublicKeys, plaintext)
}

/** A detached, armored signature over a MIME part, for `multipart/signed`. */
export async function signMailDetached(key: SealedMailKey, content: Uint8Array): Promise<string> {
  return (await getCryptoWasm()).signMailDetached(key.masterKeyBase64, key.binding, key.address, key.envelope, key.fingerprint, content)
}

/** A cleartext signature of `text` (`-----BEGIN PGP SIGNED MESSAGE-----`): an Inline PGP body that is signed, not encrypted. */
export async function signMailCleartext(key: SealedMailKey, text: string): Promise<string> {
  return (await getCryptoWasm()).signMailCleartext(key.masterKeyBase64, key.binding, key.address, key.envelope, key.fingerprint, text)
}

/** {@link signMailCleartext} with a shared mailbox's key. */
export async function signMailCleartextAsGroup(key: GroupMailKey, text: string): Promise<string> {
  return (await getCryptoWasm()).signMailCleartextAsGroup(holder(key), text)
}

/** {@link signMailDetached} with a shared mailbox's key. */
export async function signMailDetachedAsGroup(key: GroupMailKey, content: Uint8Array): Promise<string> {
  return (await getCryptoWasm()).signMailDetachedAsGroup(holder(key), content)
}
