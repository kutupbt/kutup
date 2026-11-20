// Thin browser helpers. Rust/WASM owns every persistent Drive format
// (driveBlocks.ts); libsodium is retained here only as the platform CSPRNG
// for 32-byte keys.
import { getSodium } from './sodium'

export async function generateKey(): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.randombytes_buf(32)
}
