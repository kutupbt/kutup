// Per-file content-key derivation + AEAD frame encrypt/decrypt.
//
// Key model (spec §6):
//   content_key = HKDF-SHA256(ikm  = collection_master_key,
//                             salt = "kutup/file-content/v1",
//                             info = file_id-bytes)
// AEAD: XChaCha20-Poly1305 (libsodium crypto_aead_xchacha20poly1305_ietf).
// AAD = the 30-byte fixed envelope header (so the AEAD tag binds version, kind,
// docKeyId, sender, sequence, and the first 8 nonce bytes).
//
// Note on HKDF: libsodium-wrappers-sumo 0.7.x exposes the constants but not the
// crypto_kdf_hkdf_sha256_extract / _expand JS bindings; we therefore construct
// HKDF-SHA256 from crypto_auth_hmacsha256 per RFC 5869 (extract + expand).
// AEAD: the runtime exposes crypto_aead_xchacha20poly1305_ietf_*, but the .d.ts
// shipped with our pinned @types/libsodium-wrappers-sumo doesn't list them, so
// we route the calls through a small typed shim cast.

import _sodium from 'libsodium-wrappers-sumo'
import { pack, KIND, HEADER_SIZE, type Frame } from './envelope'

const ZERO_SIG = new Uint8Array(64)

// ---- HKDF-SHA256 (RFC 5869) built on libsodium HMAC-SHA256 ----------------
//
// We use the streaming HMAC API (init/update/final) because the one-shot form
// crypto_auth_hmacsha256(msg, key) enforces a 32-byte key, whereas HKDF needs
// HMAC over arbitrary-length keys (the salt in extract; the PRK in expand).

function hmacSha256(key: Uint8Array, msg: Uint8Array): Uint8Array {
  const state = _sodium.crypto_auth_hmacsha256_init(key)
  _sodium.crypto_auth_hmacsha256_update(state, msg)
  return _sodium.crypto_auth_hmacsha256_final(state)
}

function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  // PRK = HMAC-SHA256(salt, IKM)
  return hmacSha256(salt, ikm)
}

function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  // T(0) = empty;  T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
  // OKM = T(1) || T(2) || ... truncated to `length`.
  const hashLen = 32
  const n = Math.ceil(length / hashLen)
  if (n > 255) throw new Error('hkdf: requested length too large')
  const okm = new Uint8Array(n * hashLen)
  let prev: Uint8Array = new Uint8Array(0)
  for (let i = 1; i <= n; i++) {
    const buf = new Uint8Array(prev.length + info.length + 1)
    buf.set(prev, 0)
    buf.set(info, prev.length)
    buf[prev.length + info.length] = i
    const t = hmacSha256(prk, buf)
    okm.set(t, (i - 1) * hashLen)
    prev = t
  }
  return okm.slice(0, length)
}

/** HKDF-SHA256(ikm=collectionMaster, salt="kutup/file-content/v1", info=fileIdBytes). */
export async function deriveContentKey(collectionMaster: Uint8Array, fileId: string): Promise<Uint8Array> {
  await _sodium.ready
  const salt = new TextEncoder().encode('kutup/file-content/v1')
  const info = new TextEncoder().encode(fileId)
  const prk = hkdfExtract(salt, collectionMaster)
  return hkdfExpand(prk, info, 32)
}

// ---- AEAD shim: types ship without these symbols, runtime has them --------

interface AeadXChaCha20Poly1305Ietf {
  crypto_aead_xchacha20poly1305_ietf_encrypt(
    message: Uint8Array, additionalData: Uint8Array | null,
    secretNonce: null, publicNonce: Uint8Array, key: Uint8Array,
  ): Uint8Array
  crypto_aead_xchacha20poly1305_ietf_decrypt(
    secretNonce: null, ciphertext: Uint8Array, additionalData: Uint8Array | null,
    publicNonce: Uint8Array, key: Uint8Array,
  ): Uint8Array
}
const aead = _sodium as unknown as AeadXChaCha20Poly1305Ietf

async function aeadEncrypt(plaintext: Uint8Array, aad: Uint8Array, key: Uint8Array, nonce: Uint8Array): Promise<Uint8Array> {
  await _sodium.ready
  return aead.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, key)
}

async function aeadDecrypt(ct: Uint8Array, aad: Uint8Array, key: Uint8Array, nonce: Uint8Array): Promise<Uint8Array> {
  await _sodium.ready
  return aead.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, aad, nonce, key)
}

// ---- Frame build / open ---------------------------------------------------

/** Build a Frame whose ciphertext is the AEAD-encrypted plaintext under the given key model. */
async function buildFrame(
  plain: Uint8Array,
  kind: number,
  fileId: string,
  docKeyId: number,
  deviceId: bigint,
  sequence: bigint,
  collectionMaster: Uint8Array,
): Promise<Frame> {
  await _sodium.ready
  const key = await deriveContentKey(collectionMaster, fileId)
  const nonce = _sodium.randombytes_buf(24)
  // Build a draft frame so we can compute its AAD-able header bytes.
  const draft: Frame = {
    version: 1, kind, docKeyId,
    senderDeviceId: deviceId, sequence,
    nonce, ciphertext: new Uint8Array(0), signature: ZERO_SIG,
  }
  const headerBytes = pack(draft).subarray(0, HEADER_SIZE)
  const ct = await aeadEncrypt(plain, headerBytes, key, nonce)
  return { ...draft, ciphertext: ct }
}

export async function encryptYjsUpdate(
  update: Uint8Array, fileId: string, docKeyId: number,
  deviceId: bigint, sequence: bigint, collectionMaster: Uint8Array,
): Promise<Frame> {
  return buildFrame(update, KIND.YJS_UPDATE, fileId, docKeyId, deviceId, sequence, collectionMaster)
}

export async function encryptAwareness(
  update: Uint8Array, fileId: string, docKeyId: number,
  deviceId: bigint, sequence: bigint, collectionMaster: Uint8Array,
): Promise<Frame> {
  return buildFrame(update, KIND.YJS_AWARENESS, fileId, docKeyId, deviceId, sequence, collectionMaster)
}

export async function encryptOOOp(
  payload: Uint8Array, fileId: string, docKeyId: number,
  deviceId: bigint, sequence: bigint, collectionMaster: Uint8Array,
): Promise<Frame> {
  return buildFrame(payload, KIND.OO_OP, fileId, docKeyId, deviceId, sequence, collectionMaster)
}

export async function decryptOOOp(f: Frame, fileId: string, collectionMaster: Uint8Array): Promise<Uint8Array> {
  return decryptCommon(f, fileId, collectionMaster)
}

// OO_CURSOR: peer live cell-selection presence (the translucent rectangle
// over the cells the other user has selected). Ephemeral — same envelope
// + AEAD as OO_OP but with a different KIND so the relay routes it as
// broadcast-only (no file_update_log entry; selections are transient).
export async function encryptOOCursor(
  payload: Uint8Array, fileId: string, docKeyId: number,
  deviceId: bigint, sequence: bigint, collectionMaster: Uint8Array,
): Promise<Frame> {
  return buildFrame(payload, KIND.OO_CURSOR, fileId, docKeyId, deviceId, sequence, collectionMaster)
}

export async function decryptOOCursor(f: Frame, fileId: string, collectionMaster: Uint8Array): Promise<Uint8Array> {
  return decryptCommon(f, fileId, collectionMaster)
}

export async function decryptYjsUpdate(f: Frame, fileId: string, collectionMaster: Uint8Array): Promise<Uint8Array> {
  return decryptCommon(f, fileId, collectionMaster)
}

export async function decryptAwareness(f: Frame, fileId: string, collectionMaster: Uint8Array): Promise<Uint8Array> {
  return decryptCommon(f, fileId, collectionMaster)
}

async function decryptCommon(f: Frame, fileId: string, collectionMaster: Uint8Array): Promise<Uint8Array> {
  await _sodium.ready
  const key = await deriveContentKey(collectionMaster, fileId)
  const headerBytes = pack(f).subarray(0, HEADER_SIZE)
  return aeadDecrypt(f.ciphertext, headerBytes, key, f.nonce)
}
