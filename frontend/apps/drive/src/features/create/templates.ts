import { DOCUMENT_KINDS, newDocument, uniqueName, type DocumentKind } from '@kutup/drive-core/documents'
import { encodeListJson, LIST_EXTENSION, LIST_MIME } from '@kutup/map/list'

// What "New → …" creates. Each is an ordinary encrypted upload of a small
// starting file; the editors take it from there. The documents are the
// Office home's too (@kutup/drive-core/documents); a map is Drive's and
// Maps' alone.

export const NEW_DOCUMENTS = [...DOCUMENT_KINDS, 'map'] as const
export type NewDocument = (typeof NEW_DOCUMENTS)[number]

export { uniqueName }

export function newDocumentFile(type: NewDocument, baseName: string, taken: Iterable<string>): File {
  if (type !== 'map') return newDocument(type satisfies DocumentKind, baseName, taken)
  const name = uniqueName(baseName, LIST_EXTENSION, taken)
  return new File([encodeListJson([]).slice()], name, { type: LIST_MIME })
}
