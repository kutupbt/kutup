// Theme handling.
//
// Default behaviour: follow the OS colour-scheme (`prefers-color-scheme`),
// falling back to light when it can't be determined. The user's explicit
// choice via the navbar light/dark toggle wins and persists (once toggled,
// the choice is "pinned" — it no longer tracks the OS). The persisted value
// is a *preference* — `'light' | 'dark' | 'system'` — stored under
// `kutup-theme`; consumers get a *resolved* `'light' | 'dark'`.
//
// The flash-free first paint is handled by a tiny inline <script> in
// index.html that mirrors the resolution logic below and sets the
// `<html>` class before the body is painted.

/** A resolved theme — what consumers (CodeMirror, Excalidraw, the toggle
 *  icon) want. */
export type Theme = 'light' | 'dark'
/** The persisted preference — adds `'system'` (= follow the OS). */
export type ThemePreference = Theme | 'system'

const KEY = 'kutup-theme'

export function isThemePreference(v: unknown): v is ThemePreference {
  return v === 'light' || v === 'dark' || v === 'system'
}

/**
 * The OS colour-scheme preference. `matchMedia` always returns a
 * MediaQueryList — if the platform doesn't report a preference (some
 * minimal Linux setups, or no `matchMedia` at all), `matches` is `false`
 * → `'light'`. That *is* the "can't tell → light" rule.
 */
export function getSystemTheme(): Theme {
  return typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-color-scheme: dark)').matches
    ? 'dark'
    : 'light'
}

/** The stored preference. Defaults to `'system'` when nothing valid is
 *  stored (a fresh install, private-browsing, garbage value). */
export function getThemePreference(): ThemePreference {
  let v: string | null = null
  try {
    v = localStorage.getItem(KEY)
  } catch {
    // localStorage may throw in private mode / disabled-storage contexts.
  }
  return isThemePreference(v) ? v : 'system'
}

export function resolveTheme(pref: ThemePreference): Theme {
  return pref === 'system' ? getSystemTheme() : pref
}

/** The current *resolved* theme — `'light' | 'dark'`. */
export function getTheme(): Theme {
  return resolveTheme(getThemePreference())
}

type Listener = (t: Theme) => void
const listeners = new Set<Listener>()

/**
 * Apply a *preference*: set the resolved `<html>` class + `color-scheme`,
 * persist the preference, and notify in-tab listeners with the resolved
 * theme. `applyTheme('system')` follows the OS (and persists `'system'`
 * so it keeps following on the next launch); `applyTheme('light' |
 * 'dark')` pins.
 */
export function applyTheme(pref: ThemePreference): void {
  const resolved = resolveTheme(pref)
  if (typeof document !== 'undefined') {
    const d = document.documentElement
    d.classList.toggle('dark', resolved === 'dark')
    d.classList.toggle('light', resolved === 'light')
    d.style.colorScheme = resolved // native form controls / scrollbars
  }
  try {
    localStorage.setItem(KEY, pref)
  } catch {
    // ignore — storage unavailable
  }
  listeners.forEach((l) => l(resolved))
}

/** Binary toggle: flips the resolved theme and pins the choice (leaves
 *  `'system'` mode if it was in it). */
export function toggleTheme(): Theme {
  const next: Theme = getTheme() === 'dark' ? 'light' : 'dark'
  applyTheme(next)
  return next
}

/** Switch back to following the OS. Exported for a future "use system"
 *  control; not wired into any UI yet. */
export function followSystemTheme(): void {
  applyTheme('system')
}

// In-tab pub/sub. Cross-tab sync uses the native `storage` event — see
// hooks/useTheme.ts. Returns an unsubscribe function.
export function subscribeTheme(cb: Listener): () => void {
  listeners.add(cb)
  return () => {
    listeners.delete(cb)
  }
}

let systemWatcherInstalled = false

/**
 * Live-track the OS colour-scheme: when it changes *and* the user hasn't
 * pinned a choice (preference is `'system'`), re-apply. Call once at boot.
 * Idempotent; no-op when `matchMedia` is unavailable.
 */
export function initSystemThemeWatcher(): void {
  if (
    systemWatcherInstalled ||
    typeof window === 'undefined' ||
    typeof window.matchMedia !== 'function'
  ) {
    return
  }
  systemWatcherInstalled = true
  const mql = window.matchMedia('(prefers-color-scheme: dark)')
  const onChange = () => {
    if (getThemePreference() === 'system') applyTheme('system')
  }
  if (typeof mql.addEventListener === 'function') {
    mql.addEventListener('change', onChange)
  } else if (
    typeof (mql as MediaQueryList & { addListener?: unknown }).addListener === 'function'
  ) {
    // Older Safari / WebKit
    ;(mql as unknown as { addListener(cb: () => void): void }).addListener(onChange)
  }
}
