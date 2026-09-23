/**
 * Folder colours. Stored on the server as `#rrggbb` (the CLI's `kutup color`
 * writes the same), so this list is only what the picker offers: any valid
 * hex set elsewhere still renders. They are user data, not theme tokens —
 * mid tones that read on both the light and the dark background. A folder
 * without one is neutral (`--kind-folder`).
 */
export const FOLDER_COLORS = [
  { hex: '#ef4444', name: 'red' },
  { hex: '#f97316', name: 'orange' },
  { hex: '#f59e0b', name: 'amber' },
  { hex: '#22c55e', name: 'green' },
  { hex: '#14b8a6', name: 'teal' },
  { hex: '#38bdf8', name: 'ice' },
  { hex: '#3b82f6', name: 'blue' },
  { hex: '#a855f7', name: 'purple' },
  { hex: '#ec4899', name: 'pink' },
] as const

const HEX = /^#[0-9a-f]{6}$/i

/** The colour to draw, or null for the neutral default (and anything malformed). */
export function folderHex(color: string | null): string | null {
  return color && HEX.test(color) ? color.toLowerCase() : null
}
