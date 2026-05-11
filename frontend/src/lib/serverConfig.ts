// Tauri-only server-URL config.
//
// In a Tauri release build the frontend is served from `tauri://localhost/`
// (Linux/macOS) or `http://tauri.localhost/` (Windows), so the user must
// tell the app which kutup backend to talk to — exactly like Nextcloud or
// Mastodon. This module owns the read/write/clear of that URL plus the
// normalization rules clients should apply before persisting.
//
// Web (`!isTauri`) builds always return null — there is no server-URL
// step on the web, the backend is same-origin.

import { isTauri } from './isTauri'

const STORE_FILE = 'kutup.dat'
const KEY = 'serverUrl'

// Cache the Store handle. Dynamic import keeps @tauri-apps/plugin-store
// out of the web bundle's critical path.
let storePromise: Promise<unknown> | null = null
async function getStore(): Promise<{
  get: <T>(key: string) => Promise<T | null | undefined>
  set: (key: string, value: unknown) => Promise<void>
  delete: (key: string) => Promise<boolean>
  save: () => Promise<void>
}> {
  if (!isTauri) {
    throw new Error('serverConfig: not running in Tauri')
  }
  if (!storePromise) {
    storePromise = import('@tauri-apps/plugin-store').then(({ load }) =>
      load(STORE_FILE, { autoSave: true, defaults: {} }),
    )
  }
  // Type-cast: the Store API surface we use is a small subset.
  return storePromise as unknown as ReturnType<typeof getStore>
}

// normalizeServerUrl applies the production-grade input cleanup:
//   • trim whitespace
//   • prepend https:// if the user typed a bare host
//   • refuse http:// unless host is localhost / 127.0.0.1 / ::1 / *.local
//   • strip trailing slash
//   • reject anything URL.parse() can't handle
//
// Returns the normalized string on success or { error } on rejection. The
// error code is i18n-safe (the caller maps it to a translated string).
export type NormalizeResult =
  | { ok: true; url: string }
  | { ok: false; error: 'empty' | 'invalid' | 'insecure-http' }

export function normalizeServerUrl(input: string): NormalizeResult {
  const trimmed = input.trim()
  if (!trimmed) return { ok: false, error: 'empty' }

  // If the input already carries a `<scheme>://` prefix, accept it only if
  // the scheme is https or http. Otherwise prepend https://. This blocks
  // silent rewrites of garbage like `htp://...` into `https://htp://...`.
  const schemeMatch = trimmed.match(/^([a-z][a-z0-9+.-]*):\/\//i)
  let raw = trimmed
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase()
    if (scheme !== 'https' && scheme !== 'http') {
      return { ok: false, error: 'invalid' }
    }
  } else {
    raw = 'https://' + raw
  }

  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return { ok: false, error: 'invalid' }
  }

  // Hostname must be non-empty and look like a real authority — no spaces,
  // no path-as-host smuggling.
  if (!url.hostname || /\s/.test(url.hostname)) {
    return { ok: false, error: 'invalid' }
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return { ok: false, error: 'invalid' }
  }

  if (url.protocol === 'http:') {
    const h = url.hostname.toLowerCase()
    const isLocal =
      h === 'localhost' ||
      h === '127.0.0.1' ||
      h === '::1' ||
      h.endsWith('.local')
    if (!isLocal) return { ok: false, error: 'insecure-http' }
  }

  // Drop trailing slash + any path/query/hash so we always store a bare origin.
  const origin = url.origin
  return { ok: true, url: origin }
}

export async function getServerUrl(): Promise<string | null> {
  if (!isTauri) return null
  try {
    const store = await getStore()
    const v = await store.get<string>(KEY)
    return typeof v === 'string' && v.length > 0 ? v : null
  } catch {
    return null
  }
}

export async function setServerUrl(url: string): Promise<void> {
  if (!isTauri) return
  const store = await getStore()
  await store.set(KEY, url)
  await store.save()
}

export async function clearServerUrl(): Promise<void> {
  if (!isTauri) return
  try {
    const store = await getStore()
    await store.delete(KEY)
    await store.save()
  } catch {
    // best-effort
  }
}
