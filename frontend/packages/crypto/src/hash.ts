import { getCryptoWasm } from './rustWasm'

/**
 * The suite's hash for the web apps (docs/plans/crypto-primitives.md,
 * `SuiteParams::hash`; suite 1: SHA-256), as kutup_crypto::primitives::hash
 * computes it in Rust. Everything outside @kutup/crypto hashes through here;
 * ESLint refuses `crypto.subtle` anywhere else.
 */
export async function hash(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data as BufferSource))
}

/** The suite's hash, fed in parts (a stream too large to hold). */
export interface Hasher {
  update(chunk: Uint8Array): void
  /** The digest; the hasher is spent. */
  digest(): Uint8Array
}

/** A new streaming suite hash, through kutup-crypto (WASM). */
export async function createHasher(): Promise<Hasher> {
  const module = await getCryptoWasm()
  const hasher = new module.SuiteHasher()
  return {
    update: (chunk) => hasher.update(chunk),
    digest: () => {
      try {
        return hasher.finish()
      } finally {
        hasher.free()
      }
    },
  }
}

/** Lower-case hex of a digest. */
export function toHex(digest: Uint8Array): string {
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('')
}
