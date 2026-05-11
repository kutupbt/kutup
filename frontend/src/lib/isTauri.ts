// Runtime detection: are we inside the Tauri native shell?
//
// Tauri 2 injects `__TAURI_INTERNALS__` onto window before any user JS runs,
// so this check is safe to evaluate eagerly (no race). Use it to fall back
// from "open in new tab" web behaviour to in-window React Router navigation,
// since Tauri's WebView blocks `window.open(..., '_blank')` and routes
// `target="_blank"` links to the system browser.
export const isTauri =
  typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window
