// Resolves the API origin the rest of the app talks to.
//
// • Web: always `/api` (same-origin, no Tauri config involved).
// • Tauri: `${serverUrl}/api` where `serverUrl` comes from the Store-backed
//   serverConfig. In Tauri release the frontend is served from
//   `tauri://localhost/`, so a bare `/api` would resolve against the Tauri
//   custom-protocol origin and fail.
//
// The cache lives for the lifetime of the page so axios + tus-js-client +
// raw fetch sites can all read a single canonical value synchronously.
// `resolveApiBase()` must be awaited once at app boot (App.tsx) before
// the first render that uses the axios client. The "switch server" flow
// calls `invalidateApiBase()` before navigating so the next resolve picks
// up the new URL.

import { isTauri } from './isTauri'
import {
  getServerUrl,
  getServerInsecure,
  primeInsecureCache,
  resetInsecureCache,
} from './serverConfig'

let cached: string | null = null
let warmupPromise: Promise<string> | null = null

export async function resolveApiBase(): Promise<string> {
  if (cached !== null) return cached
  if (warmupPromise) return warmupPromise
  warmupPromise = (async () => {
    if (!isTauri) {
      cached = '/api'
      return cached
    }
    // Read both server-config values from the Store while we're here, and
    // prime the synchronous insecure-TLS cache the global-fetch wrapper
    // depends on.
    const [url, insecure] = await Promise.all([
      getServerUrl(),
      getServerInsecure(),
    ])
    primeInsecureCache(insecure)
    cached = url ? `${url}/api` : '/api'
    return cached
  })()
  return warmupPromise
}

// Synchronous accessor. Throws if called before `resolveApiBase()` settles
// — that's always a caller bug; the boot path is supposed to warm the
// cache before any route mounts.
export function apiBase(): string {
  if (cached === null) {
    throw new Error('apiBase() called before resolveApiBase() settled')
  }
  return cached
}

export function invalidateApiBase(): void {
  cached = null
  warmupPromise = null
  resetInsecureCache()
}
