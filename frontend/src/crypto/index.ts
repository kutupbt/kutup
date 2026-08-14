// High-level crypto operations for registration and login flows.
import { getSodium } from './sodium'
import {
  ACCOUNT_PROTECTION_DEFAULTS,
  deriveAccountProtectionKeys,
  deriveRecoveryAuthProof,
  generateAccountProtectionSalt,
} from './kdf'
import { fromBase64, toBase64 } from './base64'
import { generateKey } from './symmetric'
import {
  ACCOUNT_ENVELOPE_PURPOSE,
  openAccountEnvelope,
  sealAccountEnvelope,
} from './accountEnvelope'
import { deriveAccountIdentityKeys } from './identity'
import { encodeMnemonic } from './mnemonic'

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
export { decodeMnemonic, validateMnemonic } from './mnemonic'
export {
  ACCOUNT_PROTECTION_DEFAULTS,
  ACCOUNT_PROTECTION_SUITE_V1,
  deriveAccountProtectionKeys,
  deriveRecoveryAuthProof,
  generateAccountProtectionSalt,
} from './kdf'
export { generateKey } from './symmetric'
export { fromBase64, toBase64 } from './base64'
export { deriveAccountIdentityKeys } from './identity'
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
export { openNamedShareEnvelope, sealNamedShareEnvelope } from './namedShare'
export type { NamedShareContextV1 } from './namedShare'
export {
  openPublicLinkCollectionKeyV1,
  sealPublicLinkCollectionKeyV1,
} from './publicLink'
export type { PublicLinkCollectionContextV1 } from './publicLink'
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
  openFileRecordV1,
  renameFileRecordV1,
} from './fileRecord'
export type {
  CreatedFileRecordV1,
  FileMetadataV1,
  FileWireV1,
} from './fileRecord'
export {
  ACCOUNT_ENVELOPE_PURPOSE,
  openAccountEnvelope,
  sealAccountEnvelope,
} from './accountEnvelope'

export interface RegistrationKeys {
  // For API call
  masterKeyEnvelope: string      // canonical base64 AccountEnvelopeV1
  recoveryKeyEnvelope: string    // canonical base64 AccountEnvelopeV1
  drivePrivateKeyEnvelope: string // canonical base64 AccountEnvelopeV1
  publicKey: string             // base64
  accountAuthorityPublicKey: string
  accountAuthorityKeyId: string
  accountIncarnationId: string
  driveSigningPublicKey: string
  accountProtectionSuite: number
  accountProtectionSalt: string // base64
  argonMemoryKib: number
  argonIterations: number
  argonParallelism: number
  loginKey: string              // base64 — sent to server for bcrypt storage
  recoveryProof: string         // base64 derived proof; cannot decrypt the recovery wrap
  // For display to user (NEVER sent to server)
  mnemonic: string              // 24-word BIP39
  // In-memory only — held in Redux, never persisted
  masterKey: Uint8Array
  privateKey: Uint8Array
}

// generateRegistrationKeys derives the full Ente-style key hierarchy.
// This runs in the KDF web worker for the Argon2id calls.
export async function generateRegistrationKeys(
  password: string,
  loginEmail: string,
): Promise<RegistrationKeys> {
  const sodium = await getSodium()

  // 1. Generate master key (256-bit random, NEVER leaves client unencrypted)
  const masterKey = sodium.randombytes_buf(32)

  // 2. Generate recovery key (256-bit random → BIP39 mnemonic, shown once)
  const recoveryKeyEntropy = sodium.randombytes_buf(32)
  const mnemonic = encodeMnemonic(recoveryKeyEntropy)

  // 3. One Argon2id root; Rust expands purpose-separated KEK and login keys.
  const accountProtectionSalt = generateAccountProtectionSalt()
  const accountProtection = {
    ...ACCOUNT_PROTECTION_DEFAULTS,
    salt: toBase64(accountProtectionSalt),
  }
  const { keyEncryptionKey, loginKey } = await deriveAccountProtectionKeys(
    password,
    accountProtection,
  )
  const recoveryProof = await deriveRecoveryAuthProof(
    toBase64(recoveryKeyEntropy),
    loginEmail,
  )

  // 5. Derive the purpose-separated account identity. Account keys and their
  // typed private-key envelope are owned by the canonical Rust implementation.
  const accountIdentity = await deriveAccountIdentityKeys(toBase64(masterKey))
  const driveHpkePublicKey = fromBase64(accountIdentity.driveHpkePublicKey)
  const driveHpkePrivateKey = fromBase64(accountIdentity.driveHpkePrivateKey)

  // 6–8. Rust owns the suite-bearing, purpose- and account-bound envelopes.
  const masterKeyEnvelope = await sealAccountEnvelope(
    masterKey,
    keyEncryptionKey,
    ACCOUNT_ENVELOPE_PURPOSE.passwordMasterKey,
    loginEmail,
  )
  const recoveryKeyEnvelope = await sealAccountEnvelope(
    masterKey,
    recoveryKeyEntropy,
    ACCOUNT_ENVELOPE_PURPOSE.recoveryMasterKey,
    loginEmail,
  )
  const drivePrivateKeyEnvelope = await sealAccountEnvelope(
    driveHpkePrivateKey,
    masterKey,
    ACCOUNT_ENVELOPE_PURPOSE.driveHpkePrivateKey,
    loginEmail,
  )

  return {
    masterKeyEnvelope,
    recoveryKeyEnvelope,
    drivePrivateKeyEnvelope,
    publicKey: toBase64(driveHpkePublicKey),
    accountAuthorityPublicKey: accountIdentity.authorityPublicKey,
    accountAuthorityKeyId: accountIdentity.authorityKeyId,
    accountIncarnationId: accountIdentity.incarnationId,
    driveSigningPublicKey: accountIdentity.driveSigningPublicKey,
    accountProtectionSuite: accountProtection.suite,
    accountProtectionSalt: accountProtection.salt,
    argonMemoryKib: accountProtection.memoryKib,
    argonIterations: accountProtection.iterations,
    argonParallelism: accountProtection.parallelism,
    loginKey: toBase64(loginKey),
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

// decryptMasterKey runs after login — decrypts masterKey using derived keyEncryptionKey.
export async function decryptMasterKey(
  masterKeyEnvelope: string,
  keyEncryptionKey: Uint8Array,
  loginEmail: string,
): Promise<Uint8Array> {
  return openAccountEnvelope(
    masterKeyEnvelope,
    keyEncryptionKey,
    ACCOUNT_ENVELOPE_PURPOSE.passwordMasterKey,
    loginEmail,
  )
}

export async function decryptPrivateKey(
  drivePrivateKeyEnvelope: string,
  masterKey: Uint8Array,
  loginEmail: string,
): Promise<Uint8Array> {
  return openAccountEnvelope(
    drivePrivateKeyEnvelope,
    masterKey,
    ACCOUNT_ENVELOPE_PURPOSE.driveHpkePrivateKey,
    loginEmail,
  )
}
