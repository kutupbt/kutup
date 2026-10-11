/**
 * Loads cut off mid-fetch are tried again. Chrome aborts requests in flight
 * when the device's network changes (Wi-Fi, a VPN going up;
 * `net::ERR_NETWORK_CHANGED`), and a later fetch usually goes through. Only
 * a failure to load is retried, never a real error such as bad input or a
 * failed decryption.
 */

/** The pauses before the second, third and fourth tries: about 3.5 s in all. */
export const BACKOFF_MS: readonly number[] = [500, 1000, 2000]

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

/** A script, worker or WASM file that could not be fetched. */
export class LoadFailure extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'LoadFailure'
  }
}

// What browsers say when a module, a fetch or a worker script did not load:
// Chrome, Firefox and Safari.
const LOAD_MESSAGES = [
  /Failed to fetch dynamically imported module/i,
  /error loading dynamically imported module/i,
  /Importing a module script failed/i,
  /Failed to fetch/i,
  /NetworkError/i,
  /^Load failed$/i,
]

/** Whether `error` is a failure to load (worth another try), not a real error. */
export function isLoadFailure(error: unknown): boolean {
  if (error instanceof LoadFailure) return true
  return error instanceof TypeError && LOAD_MESSAGES.some((pattern) => pattern.test(error.message))
}

/**
 * Runs `attempt` (given its number, 0 first) until it works, a real error
 * comes, or the tries run out; it waits `backoff[n]` before try `n + 1`.
 */
export async function retryLoad<T>(attempt: (n: number) => Promise<T>, backoff: readonly number[] = BACKOFF_MS): Promise<T> {
  for (let n = 0; ; n++) {
    try {
      return await attempt(n)
    } catch (error) {
      if (n >= backoff.length || !isLoadFailure(error)) throw error
      await pause(backoff[n])
    }
  }
}

/** The script a failed dynamic import names (Chrome and Firefox put its URL in the message). */
export function failedModuleUrl(error: unknown): string | null {
  const message = error instanceof Error ? error.message : String(error)
  return /https?:\/\/[^\s'"]+\.m?js/.exec(message)?.[0] ?? null
}

/** `url` as a module the page has not tried yet: try `n` of it. */
export function freshUrl(url: string, n: number): string {
  return `${url}${url.includes('?') ? '&' : '?'}retry=${n}`
}

/**
 * A dynamic import (`() => import('…')`) retried as [`retryLoad`] does. The
 * browser remembers a failed module for the page's lifetime, so importing
 * the same URL again fails again without a fetch: each retry loads the chunk
 * the error named under a fresh URL, a new module record.
 */
export function retryImport<T>(load: () => Promise<T>, backoff: readonly number[] = BACKOFF_MS): Promise<T> {
  let url: string | null = null
  return retryLoad(async (n) => {
    if (n > 0 && url) return (await import(/* @vite-ignore */ freshUrl(url, n))) as T
    try {
      return await load()
    } catch (error) {
      url ??= failedModuleUrl(error)
      throw error
    }
  }, backoff)
}
