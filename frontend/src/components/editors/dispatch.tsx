// Maps a filename's extension to a collab-editor component, or null for fall-through
// to the existing preview/download UI. Two flavors:
// - chooseEditor: text/markdown/code → CodeMirror+Yjs CollabEditor.
// - chooseOfficeEditor: .docx/.xlsx/.pptx → OnlyOffice bridge.
import { lazy, type ComponentType } from 'react'

const TextCollabEditor = lazy(() => import('./TextCollabEditor'))
const OfficeEditor = lazy(() => import('./office/OfficeEditor'))

const TEXT_EXT = new Set([
  'md', 'markdown', 'txt',
  'go', 'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx',
  'py', 'rs', 'json', 'yaml', 'yml',
  'html', 'htm', 'css', 'toml', 'sh', 'sql',
  'dockerfile', 'nix',
])

const OFFICE_EXT = new Set(['docx', 'xlsx', 'pptx'])

export interface CollabEditorProps {
  fileId: string
  filename: string
  collectionMaster: Uint8Array
  /** Optional plaintext seed for cold-start (no Yjs snapshot yet). */
  initialContent?: string
}

export interface OfficeEditorProps {
  fileId: string
  filename: string
  collectionMaster: Uint8Array
  /** Decrypted file bytes (the OOXML blob), if the file already exists.
   *  Undefined when creating a brand-new doc — phase 2d. */
  initialBytes?: Uint8Array
}

export function chooseEditor(filename: string): ComponentType<CollabEditorProps> | null {
  const ext = filename.split('.').pop()?.toLowerCase() ?? ''
  if (TEXT_EXT.has(ext)) return TextCollabEditor
  return null
}

export function chooseOfficeEditor(filename: string): ComponentType<OfficeEditorProps> | null {
  const ext = filename.split('.').pop()?.toLowerCase() ?? ''
  if (OFFICE_EXT.has(ext)) return OfficeEditor
  return null
}
