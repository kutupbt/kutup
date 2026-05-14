/**
 * Colored folder icon — the mobile, rounded variant.
 *
 * Color resolution piggybacks on the desktop's `folderHex()` (in
 * `frontend/src/components/drive/FolderIcon.tsx`) so a folder with `color`
 * = "amber" / "red" / etc. renders the same hue on both surfaces. The
 * geometry stays distinct on purpose: desktop is a flat Lucide-style shape
 * (more rigid), mobile is the design's softer two-tone tab + body card.
 *
 * The body is a lightened wash of the icon hex (alpha 0.25 over white), so
 * the two pieces read as one folder rather than separate elements.
 */
import { folderHex } from '@/components/drive/FolderIcon'

/** Accept any string (or null/undefined) so we can pass kutup's `Collection.color`
 *  directly without a cast. `folderHex` handles unknown values via fallback. */
export type FolderColorName = string | null | undefined

export function getFolderHex(color: FolderColorName): string {
  return folderHex(color ?? null)
}

interface FolderSVGProps {
  color?: FolderColorName
  /** Pixel size of the rendered folder. Default 44. */
  size?: number
}

export function FolderSVG({ color, size = 44 }: FolderSVGProps) {
  const hex = folderHex(color ?? null)
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      aria-hidden="true"
    >
      {/* Tab + spine — solid hex. */}
      <path
        d="M4 18h40v-3a3 3 0 0 0-3-3H22l-3-4H7a3 3 0 0 0-3 3v7z"
        fill={hex}
      />
      {/* Body — lightened wash of the same hex via fill-opacity. */}
      <rect x="4" y="18" width="40" height="24" rx="3.5" fill={hex} fillOpacity="0.30" />
      {/* Faint divider where tab meets body. */}
      <rect x="4" y="18" width="40" height="2.5" fill={hex} opacity="0.22" />
    </svg>
  )
}
