// Which collaborative editor owns a file, by extension. Kept free of React
// and of the editors themselves so downloads and the explorer can ask
// without pulling CodeMirror, Excalidraw or the OnlyOffice bridge in.

export type EditorKind = 'text' | 'office' | 'whiteboard'

const TEXT_EXT = new Set([
  'md', 'markdown', 'txt',
  'go', 'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx',
  'py', 'rs', 'json', 'yaml', 'yml',
  'html', 'htm', 'css', 'toml', 'sh', 'sql',
  'dockerfile', 'containerfile', 'nix',
  // C / C++
  'c', 'h', 'cpp', 'cc', 'cxx', 'c++', 'hpp', 'hh', 'hxx', 'h++',
  // Other
  'java', 'php', 'phtml',
  // SVG is left to the image viewer: people expect to see the picture.
  'xml', 'xsl', 'xsd',
  'bash', 'zsh', 'fish',
  'rb', 'rake', 'gemspec',
  'pl', 'pm',
  'ps1', 'psm1',
  'lua', 'swift',
])

const OFFICE_EXT = new Set(['docx', 'xlsx', 'pptx'])

const WHITEBOARD_EXT = new Set(['excalidraw'])

export function extensionOf(filename: string): string {
  const dot = filename.lastIndexOf('.')
  // "Dockerfile" has no dot: the whole name is the "extension".
  return (dot < 0 ? filename : filename.slice(dot + 1)).toLowerCase()
}

export function editorKindFor(filename: string): EditorKind | null {
  const ext = extensionOf(filename)
  if (TEXT_EXT.has(ext)) return 'text'
  if (OFFICE_EXT.has(ext)) return 'office'
  if (WHITEBOARD_EXT.has(ext)) return 'whiteboard'
  return null
}

/**
 * Whether a file opens on the Office site: what is edited there (notes and
 * code, office documents, whiteboards) and PDFs. Everything else opens in
 * Drive (docs/architecture.md, "File editor route").
 */
export function opensInOffice(filename: string): boolean {
  return editorKindFor(filename) !== null || extensionOf(filename) === 'pdf'
}
