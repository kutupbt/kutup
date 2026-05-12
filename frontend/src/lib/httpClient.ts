// HTTP transport for the Tauri shell.
//
// The webview's own `fetch` / `XMLHttpRequest` cannot be told to skip TLS
// verification, and they enforce CORS. `tauri-plugin-http`'s `fetch` (Rust /
// reqwest under the hood) can do both: it bypasses CORS *and* accepts a
// `danger` option for self-signed / hostname-mismatched certs.
//
// `installTauriFetch()` swaps `globalThis.fetch` for a thin wrapper around the
// plugin's fetch when running in Tauri. Everything that uses `fetch` —
// `restoreSession`, `streamDownload`, and axios once its adapter is set to
// `'fetch'` — then transparently goes through the plugin, picking up the
// per-server "skip TLS verification" flag from `serverConfig`.
//
// On the web this module is inert (no monkeypatch, native fetch unchanged).
//
// NOT covered: `tus-js-client` uses XHR, not fetch — large-file uploads still
// go through the webview's TLS stack. With "skip TLS verification" enabled
// they will fail against a self-signed server; use a server URL whose cert is
// valid (matching hostname) for uploads. Routing tus through the plugin is a
// follow-up.

import { isTauri } from './isTauri'
import { serverInsecureSync } from './serverConfig'

let installed = false

// The plugin's fetch is loaded lazily so the web bundle never pulls it in.
type PluginFetch = (
  input: string | URL | Request,
  init?: RequestInit & {
    danger?: { acceptInvalidCerts?: boolean; acceptInvalidHostnames?: boolean }
    connectTimeout?: number
  },
) => Promise<Response>

let pluginFetchPromise: Promise<PluginFetch> | null = null
function loadPluginFetch(): Promise<PluginFetch> {
  if (!pluginFetchPromise) {
    pluginFetchPromise = import('@tauri-apps/plugin-http').then(
      (m) => m.fetch as unknown as PluginFetch,
    )
  }
  return pluginFetchPromise
}

// httpFetch — fetch routed through tauri-plugin-http in Tauri (with the
// danger flag from the cached server config), or native fetch on the web.
// `forceInsecure` lets a caller (the server-select probe) opt in before the
// flag has been persisted/cached.
export async function httpFetch(
  input: string | URL | Request,
  init?: RequestInit,
  forceInsecure?: boolean,
): Promise<Response> {
  if (!isTauri) return nativeFetch(input, init)
  const pf = await loadPluginFetch()
  const insecure = forceInsecure ?? serverInsecureSync()
  return pf(input, {
    ...init,
    danger: insecure
      ? { acceptInvalidCerts: true, acceptInvalidHostnames: true }
      : undefined,
  })
}

// Keep a reference to the genuine fetch so httpFetch can fall back to it on
// web and so installTauriFetch is idempotent.
const nativeFetch: typeof globalThis.fetch =
  typeof globalThis !== 'undefined' && globalThis.fetch
    ? globalThis.fetch.bind(globalThis)
    : (() => {
        throw new Error('no global fetch')
      }) as unknown as typeof globalThis.fetch

// installTauriFetch — replace globalThis.fetch with the plugin-backed wrapper.
// Call once at app boot, before anything issues a request. No-op on web and on
// repeat calls.
export function installTauriFetch(): void {
  if (installed || !isTauri || typeof globalThis === 'undefined') return
  installed = true
  globalThis.fetch = ((input: Parameters<typeof httpFetch>[0], init?: RequestInit) =>
    httpFetch(input, init)) as typeof globalThis.fetch
}
