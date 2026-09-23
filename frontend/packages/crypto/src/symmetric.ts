// Thin browser helpers. Rust/WASM owns every persistent Drive format;
// libsodium is retained here only as the platform CSPRNG for 32-byte keys.
import { getSodium } from './sodium'
import {
  decryptFileBlobV1,
  encryptFileBlobV1,
  type FileBlobContextV1,
} from './fileBlob'

export async function encryptStream(
  data: Uint8Array,
  key: Uint8Array,
  context: FileBlobContextV1,
): Promise<Uint8Array> {
  return encryptFileBlobV1(data, key, context)
}

export async function decryptStream(
  encryptedData: Uint8Array,
  key: Uint8Array,
  context: FileBlobContextV1,
): Promise<Uint8Array> {
  return decryptFileBlobV1(encryptedData, key, context)
}

export async function generateKey(): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.randombytes_buf(32)
}
