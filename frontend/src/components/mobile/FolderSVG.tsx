/**
 * Colored folder icon — ported from the Claude Design handoff.
 *
 * Each color picks from a curated OKLCH palette. Pass `color` as one of
 * `FOLDER_COLOR_NAMES` (or `null` for the default sky-blue used when a folder
 * has no explicit color assigned).
 *
 * Visual structure (matches the prototype): a darker tab on top, a lighter
 * body underneath, and a faint divider line where they meet.
 */

export const FOLDER_COLORS = {
  blue: { bg: 'oklch(0.88 0.09 220)', icon: 'oklch(0.46 0.20 222)' },
  purple: { bg: 'oklch(0.88 0.08 282)', icon: 'oklch(0.44 0.20 282)' },
  green: { bg: 'oklch(0.87 0.10 152)', icon: 'oklch(0.42 0.20 152)' },
  orange: { bg: 'oklch(0.89 0.10 62)', icon: 'oklch(0.50 0.20 55)' },
  pink: { bg: 'oklch(0.88 0.09 348)', icon: 'oklch(0.46 0.20 348)' },
  default: { bg: 'oklch(0.86 0.10 212)', icon: 'oklch(0.46 0.22 218)' },
} as const

export type FolderColorName = keyof typeof FOLDER_COLORS | null | undefined

export function getFolderColors(c: FolderColorName) {
  if (c == null) return FOLDER_COLORS.default
  return FOLDER_COLORS[c] ?? FOLDER_COLORS.default
}

interface FolderSVGProps {
  color?: FolderColorName
  /** Pixel size of the rendered folder. Default 44. */
  size?: number
}

export function FolderSVG({ color, size = 44 }: FolderSVGProps) {
  const { bg, icon } = getFolderColors(color)
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      aria-hidden="true"
    >
      {/* Tab + spine (darker icon color) */}
      <path
        d="M4 18h40v-3a3 3 0 0 0-3-3H22l-3-4H7a3 3 0 0 0-3 3v7z"
        fill={icon}
      />
      {/* Body (lighter bg color) */}
      <rect x="4" y="18" width="40" height="24" rx="3.5" fill={bg} />
      {/* Faint divider where tab meets body */}
      <rect x="4" y="18" width="40" height="2.5" fill={icon} opacity="0.18" />
    </svg>
  )
}
