// libsodium-wrappers-sumo singleton — sumo build required for Argon2id.
// Standard libsodium-wrappers does NOT include Argon2id.
//
// Loaded on first use, not with the page: it is about a megabyte (its WASM
// is inlined as base64) and most pages never need it
// (docs/research/17-web-performance.md).
type Sodium = typeof import('libsodium-wrappers-sumo')

let pending: Promise<Sodium> | null = null

export function getSodium(): Promise<Sodium> {
  if (!pending) {
    pending = import('libsodium-wrappers-sumo').then(async (module) => {
      // A CommonJS module: the bundler hands it over as `default`.
      const sodium = ((module as { default?: Sodium }).default ?? module) as Sodium
      await sodium.ready
      return sodium
    })
    pending.catch(() => {
      pending = null
    })
  }
  return pending
}
