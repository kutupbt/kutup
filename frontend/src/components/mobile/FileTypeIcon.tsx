/**
 * File-type-aware icon-in-tinted-square — ported from the Claude Design
 * handoff. Maps a MIME type to one of nine icon variants (pdf / doc / sheet /
 * slides / image / text / audio / video / file) and renders the matching SVG
 * inside a square with a coordinated tint.
 *
 * The icon set is intentionally small + cohesive: every variant is a single
 * SVG path drawn over the same document-outline shape, so files feel like
 * siblings even with mixed types in a list.
 */

const FILE_ICON_PATHS = {
  pdf: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M9 13h6M9 17h6M9 9h1',
  doc: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M8 13h8M8 17h8M8 9h3',
  sheet:
    'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M8 12h8M8 16h8M8 8h3M12 12v8',
  slides: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M7 13h10v6H7z',
  image:
    'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M6.5 18l3.5-4 2.5 3 2-2 3 3',
  text: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M8 13h8M8 17h5',
  audio: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M9 17v-5l6-1v5',
  video:
    'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M10 11l6 3.5-6 3.5V11z',
  file: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6',
} as const

export type FileIconVariant = keyof typeof FILE_ICON_PATHS

interface MimeInfo {
  type: FileIconVariant
  color: string
  bg: string
}

/** Maps a MIME string to the icon variant + colors. */
export function getMimeInfo(mime: string | undefined | null): MimeInfo {
  const m = mime ?? ''
  if (m.startsWith('image/'))
    return { type: 'image', color: 'oklch(0.52 0.16 280)', bg: 'oklch(0.92 0.06 280)' }
  if (m.includes('pdf'))
    return { type: 'pdf', color: 'oklch(0.50 0.20 22)', bg: 'oklch(0.93 0.05 22)' }
  if (m.includes('excel') || m.includes('spreadsheet') || m.includes('csv'))
    return { type: 'sheet', color: 'oklch(0.44 0.18 152)', bg: 'oklch(0.91 0.06 152)' }
  if (m.includes('powerpoint') || m.includes('presentation'))
    return { type: 'slides', color: 'oklch(0.52 0.18 42)', bg: 'oklch(0.92 0.06 42)' }
  if (m.includes('word') || m.includes('document'))
    return { type: 'doc', color: 'oklch(0.48 0.18 222)', bg: 'oklch(0.91 0.06 222)' }
  if (m.startsWith('text/'))
    return { type: 'text', color: 'oklch(0.46 0.08 222)', bg: 'oklch(0.92 0.03 222)' }
  if (m.startsWith('audio/'))
    return { type: 'audio', color: 'oklch(0.50 0.18 310)', bg: 'oklch(0.91 0.06 310)' }
  if (m.startsWith('video/'))
    return { type: 'video', color: 'oklch(0.48 0.18 262)', bg: 'oklch(0.91 0.06 262)' }
  return { type: 'file', color: 'oklch(0.46 0.06 224)', bg: 'oklch(0.91 0.03 224)' }
}

interface FileTypeIconProps {
  mime?: string | null
  /** Pixel size of the rendered tile (default 40). */
  size?: number
}

export function FileTypeIcon({ mime, size = 40 }: FileTypeIconProps) {
  const info = getMimeInfo(mime)
  const path = FILE_ICON_PATHS[info.type]
  const inner = size * 0.55
  return (
    <div
      style={{
        width: size,
        height: size,
        borderRadius: size * 0.24,
        background: info.bg,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexShrink: 0,
      }}
      aria-hidden="true"
    >
      <svg
        width={inner}
        height={inner}
        viewBox="0 0 24 24"
        fill="none"
        stroke={info.color}
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d={path} />
      </svg>
    </div>
  )
}
