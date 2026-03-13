// Argon2id KDF — run in Web Worker to avoid blocking the main thread.
// Parameters match Ente's audited configuration: 64MB memory, 3 iterations, 4 threads.
import { getSodium } from './sodium'

const OPSLIMIT = 3
const MEMLIMIT = 64 * 1024 * 1024 // 64 MB
const KEYLEN = 32 // 256-bit

export async function deriveKeyEncryptionKey(
  password: string,
  kdfSalt: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.crypto_pwhash(
    KEYLEN,
    password,
    kdfSalt,
    OPSLIMIT,
    MEMLIMIT,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  )
}

export async function deriveLoginKey(
  password: string,
  loginKeySalt: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.crypto_pwhash(
    KEYLEN,
    password,
    loginKeySalt,
    OPSLIMIT,
    MEMLIMIT,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  )
}

export async function generateKDFSalt(): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES)
}
