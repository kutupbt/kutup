// High-level crypto operations for registration and login flows.
import { getSodium } from './sodium'
import { deriveKeyEncryptionKey, deriveLoginKey, generateKDFSalt } from './kdf'
import { encrypt, decrypt, generateKey } from './symmetric'
import { generateKeypair } from './asymmetric'
import { encodeMnemonic } from './mnemonic'

export { encryptStream, decryptStream } from './symmetric'
export { wrapKeyForRecipient, unwrapKeyFromSender } from './asymmetric'
export { decodeMnemonic, validateMnemonic } from './mnemonic'
export { deriveKeyEncryptionKey, deriveLoginKey, generateKDFSalt } from './kdf'
export { encrypt, decrypt, generateKey } from './symmetric'

export function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
}

export function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export interface RegistrationKeys {
  // For API call
  encryptedMasterKey: string    // base64
  masterKeyNonce: string        // base64
  encryptedRecoveryKey: string  // base64
  recoveryKeyNonce: string      // base64
  encryptedPrivateKey: string   // base64
  privateKeyNonce: string       // base64
  publicKey: string             // base64
  kdfSalt: string               // base64
  loginKeySalt: string          // base64
  loginKey: string              // base64 — sent to server for bcrypt storage
  recoveryKey: string           // base64 — sent to server as recovery proof at registration (S1-2 fix)
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
): Promise<RegistrationKeys> {
  const sodium = await getSodium()

  // 1. Generate master key (256-bit random, NEVER leaves client unencrypted)
  const masterKey = sodium.randombytes_buf(32)

  // 2. Generate recovery key (256-bit random → BIP39 mnemonic, shown once)
  const recoveryKeyEntropy = sodium.randombytes_buf(32)
  const mnemonic = encodeMnemonic(recoveryKeyEntropy)

  // 3. Generate two INDEPENDENT KDF salts
  const kdfSalt = await generateKDFSalt()
  const loginKeySalt = await generateKDFSalt()

  // 4. Derive keys from password (Argon2id, ~1-2s each)
  const keyEncryptionKey = await deriveKeyEncryptionKey(password, kdfSalt)
  const loginKey = await deriveLoginKey(password, loginKeySalt)

  // 5. Generate X25519 keypair
  const keypair = await generateKeypair()

  // 6. Encrypt masterKey with keyEncryptionKey
  const encMK = await encrypt(masterKey, keyEncryptionKey)

  // 7. Encrypt masterKey with recoveryKey (for account recovery)
  const encMKRecovery = await encrypt(masterKey, recoveryKeyEntropy)

  // 8. Encrypt privateKey with masterKey
  const encPK = await encrypt(keypair.privateKey, masterKey)

  return {
    encryptedMasterKey: toBase64(encMK.ciphertext),
    masterKeyNonce: toBase64(encMK.nonce),
    encryptedRecoveryKey: toBase64(encMKRecovery.ciphertext),
    recoveryKeyNonce: toBase64(encMKRecovery.nonce),
    encryptedPrivateKey: toBase64(encPK.ciphertext),
    privateKeyNonce: toBase64(encPK.nonce),
    publicKey: toBase64(keypair.publicKey),
    kdfSalt: toBase64(kdfSalt),
    loginKeySalt: toBase64(loginKeySalt),
    loginKey: toBase64(loginKey),
    recoveryKey: toBase64(recoveryKeyEntropy),
    mnemonic,
    masterKey,
    privateKey: keypair.privateKey,
  }
}

export interface LoginResult {
  masterKey: Uint8Array
  privateKey: Uint8Array
}

// decryptMasterKey runs after login — decrypts masterKey using derived keyEncryptionKey.
export async function decryptMasterKey(
  encryptedMasterKey: string,
  masterKeyNonce: string,
  keyEncryptionKey: Uint8Array,
): Promise<Uint8Array> {
  return decrypt(fromBase64(encryptedMasterKey), fromBase64(masterKeyNonce), keyEncryptionKey)
}

export async function decryptPrivateKey(
  encryptedPrivateKey: string,
  privateKeyNonce: string,
  masterKey: Uint8Array,
): Promise<Uint8Array> {
  return decrypt(fromBase64(encryptedPrivateKey), fromBase64(privateKeyNonce), masterKey)
}
