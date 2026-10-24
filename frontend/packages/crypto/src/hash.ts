/**
 * The suite's hash for the web apps (docs/plans/crypto-primitives.md,
 * `SuiteParams::hash`; suite 1: SHA-256), as kutup_crypto::primitives::hash
 * computes it in Rust. Everything outside @kutup/crypto hashes through here;
 * ESLint refuses `crypto.subtle` anywhere else.
 */
export async function hash(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data as BufferSource))
}
