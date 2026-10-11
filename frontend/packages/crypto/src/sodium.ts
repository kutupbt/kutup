// libsodium-wrappers-sumo singleton — sumo build required for Argon2id.
// Standard libsodium-wrappers does NOT include Argon2id.
//
// Loaded on first use, not with the page: it is about a megabyte (its WASM
// is inlined as base64) and most pages never need it
// (docs/research/18-web-performance.md).
import { retryImport } from './retry'

type Sodium = typeof import('libsodium-wrappers-sumo')

let pending: Promise<Sodium> | null = null

export function getSodium(): Promise<Sodium> {
  if (!pending) {
    // A fetch cut off by a network change is tried once more.
    pending = retryImport(() => import('libsodium-wrappers-sumo')).then(async (module) => {
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
