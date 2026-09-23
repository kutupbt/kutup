// Split a filename into base + extension. Used by the rename UI to lock
// the extension so a user can't accidentally turn `report.docx` into
// `report.txt` (which would silently break the office editor dispatch
// in components/editors/dispatch.tsx).
//
// Rules:
// - Extensions we know about (office + text editor + viewers) are
//   recognised and split out. Everything else (e.g. `Makefile`,
//   `data.tar.gz` — we keep `.gz`) is left untouched.
// - Hidden files (`.bashrc`, `.env`) keep the leading dot as part of the
//   name; no extension extracted.

const KNOWN_EXTS = new Set([
  // office
  'docx', 'xlsx', 'pptx',
  // whiteboard
  'excalidraw',
  // text / code (matches dispatch.tsx TEXT_EXT)
  'md', 'markdown', 'txt',
  'go', 'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx',
  'py', 'rs', 'json', 'yaml', 'yml',
  'html', 'htm', 'css', 'toml', 'sh', 'sql',
  'dockerfile', 'nix',
  // common viewer media
  'pdf', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp',
  'mp3', 'wav', 'ogg', 'mp4', 'webm', 'mov',
])

export interface SplitName {
  base: string
  /** Extension WITHOUT the leading dot, lowercased. Empty string if no
   *  recognised extension. */
  ext: string
}

export function splitFilename(name: string): SplitName {
  // Hidden file — no extension to extract.
  if (name.startsWith('.') && !name.slice(1).includes('.')) {
    return { base: name, ext: '' }
  }
  const dot = name.lastIndexOf('.')
  if (dot <= 0) return { base: name, ext: '' }
  const ext = name.slice(dot + 1).toLowerCase()
  if (!KNOWN_EXTS.has(ext)) return { base: name, ext: '' }
  return { base: name.slice(0, dot), ext }
}

/** Stitch a basename + extension back together. Empty ext returns base. */
export function joinFilename(base: string, ext: string): string {
  return ext ? `${base}.${ext}` : base
}
