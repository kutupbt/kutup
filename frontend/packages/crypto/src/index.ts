// High-level crypto operations for registration and login flows.
import { getSodium } from './sodium'
import { deriveRecoveryAuthProof } from './kdf'
import { fromBase64, toBase64 } from './base64'
import {
  ACCOUNT_ENVELOPE_PURPOSE,
  openAccountEnvelope,
  sealAccountEnvelope,
} from './accountEnvelope'
import { deriveAccountIdentityKeys } from './identity'

export { encryptStream, decryptStream } from './symmetric'
export {
  decryptFileBlobV1,
  encryptFileBlobV1,
  fileBlobCipherSize,
  newFileBlobStreamEncryptorV1,
  openFileBlobStreamV1,
} from './fileBlob'
export type { FileBlobContextV1 } from './fileBlob'
export {
  CHAT_MEDIA_OBJECT_HEADER_BYTES,
  CHAT_MEDIA_OBJECT_PREFIX_BYTES,
  CHAT_MEDIA_SUITE_V1,
  MAX_CHAT_MEDIA_PLAINTEXT_BYTES,
  chatAttachmentLedgerEnvelopeDigest,
  chatMediaCipherSize,
  decryptChatMediaV1,
  deriveChatAttachmentLedgerKey,
  encryptChatMediaV1,
  newChatMediaStreamEncryptorV1,
  openChatAttachmentLedger,
  openChatMediaStreamV1,
  sealChatAttachmentLedger,
} from './chatMedia'
export type {
  ChatAttachmentLedgerContextV1,
  ChatMediaStreamEncryptorV1,
} from './chatMedia'
// The recovery phrase (bip39 and its wordlists) is @kutup/crypto/mnemonic,
// kept out of this barrel so only the pages that use it load it.
export { deriveRecoveryAuthProof } from './kdf'
export { generateKey } from './symmetric'
export { fromBase64, toBase64 } from './base64'
export { deriveAccountIdentityKeys } from './identity'
export {
  DEFAULT_MAIL_KEY_FLAGS,
  MAIL_KEY_FLAGS,
  MIN_MAIL_KEY_PASSPHRASE,
  WrongKeyPassphrase,
  armorMailPublicKey,
  encryptMailMessage,
  describeExternalMailKey,
  describeExternalMailKeyDetails,
  encryptMailMessageAsGroup,
  encryptMailPgp,
  encryptMailPgpAsGroup,
  exportMailAddressKey,
  generateMailAddressKey,
  foldAddress,
  generateMailGroupKey,
  importMailAddressKey,
  inspectExternalMailKey,
  inspectMailAddressPublicKey,
  openMailGroupMessage,
  openMailMessage,
  reshareMailGroupKey,
  newMailGroupSigner,
  reshareMailGroupSigner,
  signMailGroupKeyList,
  verifyMailGroupKeyChain,
  signMailKeyList,
  verifyMailCleartext,
  verifyMailDetachedSignature,
  verifyMailGroupKeyChain,
  verifyMailKeyList,
  encryptMailMessageUnsigned,
  encryptMailPgpUnsigned,
  signMailCleartext,
  signMailCleartextAsGroup,
  signMailDetached,
  signMailDetachedAsGroup,
} from './mailKey'
export type {
  ExternalMailKey,
  GeneratedMailAddressKey,
  GeneratedMailGroupKey,
  GroupKeyChainView,
  GroupKeyMember,
  GroupSignerHolder,
  GroupMailKey,
  MailKeyEntry,
  MailKeyListInput,
  OpenedMail,
  SealedMail,
  SealedMailKey,
  SignedMailKeyList,
} from './mailKey'
export { openContactCard, openMailName, sealContactCard, sealMailName, signContactSummary, verifyContactSummary } from './contactCard'
export type { ContactSummary, MailNameKind, Revisioned } from './contactCard'
export { OlderThanSeenError, RevisionGuard, revisionGuard, memoryRevisionStore, type RevisionStore } from './revisionGuard'
export type { AccountIdentityKeysV1 } from './identity'
export {
  DRIVE_ENVELOPE_PURPOSE,
  openDriveEnvelope,
  sealDriveEnvelope,
} from './driveEnvelope'
export type { DriveEnvelopeContextV1, DriveEnvelopePurpose } from './driveEnvelope'
export {
  createCollectionEpochStatement,
  verifyCollectionEpochStatement,
} from './collectionEpoch'
export {
  openFileShareEnvelope,
  openNamedShareEnvelope,
  openProfileKeyEnvelope,
  sealFileShareEnvelope,
  sealNamedShareEnvelope,
  sealProfileKeyEnvelope,
} from './namedShare'
export type { FileShareContextV1, NamedShareContextV1, ProfileKeyPartiesV1 } from './namedShare'
export {
  openPublicLinkCollectionKeyV1,
  openPublicLinkFileKeyV1,
  sealPublicLinkCollectionKeyV1,
  sealPublicLinkFileKeyV1,
} from './publicLink'
export type { PublicLinkCollectionContextV1, PublicLinkFileContextV1 } from './publicLink'
export {
  createOwnedCollectionV1,
  openOwnedCollectionV1,
  openOwnedCollectionKeyV1,
  openSharedCollectionV1,
  renameOwnedCollectionV1,
} from './ownedCollection'
export type { CreateOwnedCollectionV1, OwnedCollectionWireV1 } from './ownedCollection'
export {
  createFileRecordV1,
  openFileMetadataV1,
  openFileRecordV1,
  rekeyFileRecordV1,
  renameFileRecordV1,
  wrapFileKeyForV1,
} from './fileRecord'
export { fileKeyAtV1, sealPreviousFileKeyV1 } from './fileKeyring'
export type { FileKeyLinkV1 } from './fileKeyring'
export type {
  CreatedFileRecordV1,
  FileMetadataV1,
  MediaMetadataV1,
  TakenFromV1,
  FileWireV1,
} from './fileRecord'
export {
  ACCOUNT_ENVELOPE_PURPOSE,
  openAccountEnvelope,
  sealAccountEnvelope,
} from './accountEnvelope'

/**
 * A new account's keys, before any password: the master key, the recovery
 * phrase and its envelope, and the account identity. The password envelope
 * comes from OPAQUE (`@kutup/crypto/opaqueWorker`), sealed under its export key.
 */
export interface AccountKeySet {
  recoveryKeyEnvelope: string // canonical base64 AccountEnvelopeV1
  drivePrivateKeyEnvelope: string // canonical base64 AccountEnvelopeV1
  publicKey: string // base64
  accountAuthorityPublicKey: string
  accountAuthorityKeyId: string
  accountIncarnationId: string
  driveSigningPublicKey: string
  recoveryProof: string // base64 derived proof; cannot decrypt the recovery wrap
  // For display to the user (never sent to the server)
  mnemonic: string // 24-word BIP39
  // In memory only
  masterKey: Uint8Array
  privateKey: Uint8Array
}

/** Fresh account keys bound to `binding` (no password involved: no Argon2id). */
export async function generateAccountKeySet(binding: string): Promise<AccountKeySet> {
  const sodium = await getSodium()
  // The master key (256-bit random, never leaves the client unencrypted) and
  // the recovery key (256-bit random, the 24-word phrase shown once).
  const masterKey = sodium.randombytes_buf(32)
  const recoveryKeyEntropy = sodium.randombytes_buf(32)
  try {
    return await sealAccountKeySet(masterKey, recoveryKeyEntropy, binding)
  } finally {
    recoveryKeyEntropy.fill(0)
  }
}

/**
 * The same keys bound to another binding (the one drawn was taken): the
 * recovery phrase and the master key stay, so nothing shown to the user
 * changes; the records bound to the binding are sealed again.
 */
export async function rebindAccountKeySet(keys: AccountKeySet, binding: string): Promise<AccountKeySet> {
  const { decodeMnemonic } = await import('./mnemonic')
  const recoveryKeyEntropy = decodeMnemonic(keys.mnemonic)
  try {
    return await sealAccountKeySet(keys.masterKey, recoveryKeyEntropy, binding)
  } finally {
    recoveryKeyEntropy.fill(0)
  }
}

async function sealAccountKeySet(masterKey: Uint8Array, recoveryKeyEntropy: Uint8Array, binding: string): Promise<AccountKeySet> {
  const { encodeMnemonic } = await import('./mnemonic')
  const mnemonic = encodeMnemonic(recoveryKeyEntropy)
  const recoveryProof = await deriveRecoveryAuthProof(toBase64(recoveryKeyEntropy), binding)
  // The purpose-separated account identity; Rust owns the keys and envelopes.
  // It derives from the master key alone, so it does not change with the binding.
  const accountIdentity = await deriveAccountIdentityKeys(toBase64(masterKey))
  const driveHpkePublicKey = fromBase64(accountIdentity.driveHpkePublicKey)
  const driveHpkePrivateKey = fromBase64(accountIdentity.driveHpkePrivateKey)
  const recoveryKeyEnvelope = await sealAccountEnvelope(
    masterKey,
    recoveryKeyEntropy,
    ACCOUNT_ENVELOPE_PURPOSE.recoveryMasterKey,
    binding,
  )
  const drivePrivateKeyEnvelope = await sealAccountEnvelope(
    driveHpkePrivateKey,
    masterKey,
    ACCOUNT_ENVELOPE_PURPOSE.driveHpkePrivateKey,
    binding,
  )
  return {
    recoveryKeyEnvelope,
    drivePrivateKeyEnvelope,
    publicKey: toBase64(driveHpkePublicKey),
    accountAuthorityPublicKey: accountIdentity.authorityPublicKey,
    accountAuthorityKeyId: accountIdentity.authorityKeyId,
    accountIncarnationId: accountIdentity.incarnationId,
    driveSigningPublicKey: accountIdentity.driveSigningPublicKey,
    recoveryProof,
    mnemonic,
    masterKey,
    privateKey: driveHpkePrivateKey,
  }
}

export interface LoginResult {
  masterKey: Uint8Array
  privateKey: Uint8Array
}

export async function decryptPrivateKey(
  drivePrivateKeyEnvelope: string,
  masterKey: Uint8Array,
  binding: string,
): Promise<Uint8Array> {
  return openAccountEnvelope(
    drivePrivateKeyEnvelope,
    masterKey,
    ACCOUNT_ENVELOPE_PURPOSE.driveHpkePrivateKey,
    binding,
  )
}
export { yjsSeedClientId } from './yjsSeed'
