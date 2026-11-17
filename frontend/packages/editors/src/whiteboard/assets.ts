// Excalidraw's hand-drawn fonts come from this app's own origin
// (`/excalidraw-assets/fonts/`, copied there by the shared Vite config), not
// from esm.sh, Excalidraw's default: the apps' policy allows fonts and
// fetches from their own origin only (docs/content-security-policy.md).
// Imported for its effect, ahead of Excalidraw itself.

declare global {
  interface Window {
    EXCALIDRAW_ASSET_PATH?: string | string[]
  }
}

if (typeof window !== 'undefined') window.EXCALIDRAW_ASSET_PATH = `${window.location.origin}/excalidraw-assets/`

export {}
