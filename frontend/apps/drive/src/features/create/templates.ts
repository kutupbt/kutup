// What "New → …" creates. Each is an ordinary encrypted upload of a small
// starting file; the editors take it from there.

export const NEW_DOCUMENTS = ['note', 'document', 'spreadsheet', 'presentation', 'whiteboard'] as const
export type NewDocument = (typeof NEW_DOCUMENTS)[number]

const EXTENSION: Record<NewDocument, string> = {
  note: 'md',
  document: 'docx',
  spreadsheet: 'xlsx',
  presentation: 'pptx',
  whiteboard: 'excalidraw',
}

const MIME: Record<NewDocument, string> = {
  note: 'text/markdown',
  document: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  spreadsheet: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  presentation: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  whiteboard: 'application/vnd.excalidraw+json',
}

/** `Untitled.docx`, then `Untitled (1).docx`, … — never an existing name (case-insensitive). */
export function uniqueName(base: string, extension: string, taken: Iterable<string>): string {
  const names = new Set([...taken].map((n) => n.toLocaleLowerCase()))
  for (let n = 0; ; n++) {
    const candidate = n === 0 ? `${base}.${extension}` : `${base} (${n}).${extension}`
    if (!names.has(candidate.toLocaleLowerCase())) return candidate
  }
}

/** The starting bytes. Office files start as a 1-byte placeholder: the editor opens an empty template and the first save writes real OOXML. */
function initialBytes(type: NewDocument, name: string): Uint8Array {
  switch (type) {
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

export function newDocumentFile(type: NewDocument, baseName: string, taken: Iterable<string>): File {
  const name = uniqueName(baseName, EXTENSION[type], taken)
  return new File([initialBytes(type, name).slice()], name, { type: MIME[type] })
}
