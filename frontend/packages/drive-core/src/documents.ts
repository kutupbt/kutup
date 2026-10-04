// The documents Kutup's own editors make and open (notes, office documents,
// whiteboards): which files they are, and what a new one starts as. Shared
// by Drive's New menu and the Office home.

export const DOCUMENT_KINDS = ['note', 'document', 'spreadsheet', 'presentation', 'whiteboard'] as const
export type DocumentKind = (typeof DOCUMENT_KINDS)[number]

/** The extension a new one gets. */
export const DOCUMENT_EXTENSION: Record<DocumentKind, string> = {
  note: 'md',
  document: 'docx',
  spreadsheet: 'xlsx',
  presentation: 'pptx',
  whiteboard: 'excalidraw',
}

export const DOCUMENT_MIME: Record<DocumentKind, string> = {
  note: 'text/markdown',
  document: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  spreadsheet: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  presentation: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  whiteboard: 'application/vnd.excalidraw+json',
}

const KIND_BY_EXTENSION: Record<string, DocumentKind> = {
  md: 'note',
  markdown: 'note',
  docx: 'document',
  xlsx: 'spreadsheet',
  pptx: 'presentation',
  excalidraw: 'whiteboard',
}

/** Which kind of document a file name is, or null for anything else. */
export function documentKindOf(name: string | null): DocumentKind | null {
  if (!name) return null
  const dot = name.lastIndexOf('.')
  if (dot < 0) return null
  return KIND_BY_EXTENSION[name.slice(dot + 1).toLowerCase()] ?? null
}

/** `Untitled.docx`, then `Untitled (1).docx`, … — never an existing name (case-insensitive). */
export function uniqueName(base: string, extension: string, taken: Iterable<string>): string {
  const names = new Set([...taken].map((n) => n.toLocaleLowerCase()))
  for (let n = 0; ; n++) {
    const candidate = n === 0 ? `${base}.${extension}` : `${base} (${n}).${extension}`
    if (!names.has(candidate.toLocaleLowerCase())) return candidate
  }
}

/**
 * The starting bytes. Office files start as a 1-byte placeholder: the editor
 * opens an empty template and the first save writes real OOXML.
 */
export function initialDocumentBytes(kind: DocumentKind, name: string): Uint8Array {
  switch (kind) {
    case 'note':
      return new TextEncoder().encode(`# ${name.replace(/\.md$/i, '')}\n\n`)
    case 'whiteboard':
      return new TextEncoder().encode(
        JSON.stringify({
          type: 'excalidraw',
          version: 2,
          source: 'kutup',
          elements: [],
          appState: { gridSize: null, viewBackgroundColor: '#ffffff' },
          files: {},
        }),
      )
    default:
      return new Uint8Array([0])
  }
}

/** A new, empty document named `baseName`, or the next free name after it. */
export function newDocument(kind: DocumentKind, baseName: string, taken: Iterable<string>): File {
  const name = uniqueName(baseName, DOCUMENT_EXTENSION[kind], taken)
  return new File([initialDocumentBytes(kind, name).slice()], name, { type: DOCUMENT_MIME[kind] })
}
