/**
 * The one random source for the web apps (docs/plans/crypto-primitives.md,
 * `SuiteParams::random`: the browser's `crypto.getRandomValues`). Everything
 * outside @kutup/crypto takes its randomness from here; ESLint refuses the
 * Web Crypto call anywhere else.
 */

/** The most `getRandomValues` fills in one call (the Web Crypto limit). */
const QUOTA = 65_536

/** Fills `view` with random bytes, in place. */
export function fillRandom<T extends Uint8Array | Uint16Array | Uint32Array>(view: T): T {
  const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
  for (let offset = 0; offset < bytes.length; offset += QUOTA) {
    crypto.getRandomValues(bytes.subarray(offset, offset + QUOTA))
  }
  return view
}

/** `length` random bytes. */
export function randomBytes(length: number): Uint8Array {
  return fillRandom(new Uint8Array(length))
}
