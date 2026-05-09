// Maps a filename's extension to a collab-editor component, or null for fall-through
// to the existing preview/download UI. Two flavors:
// - chooseEditor: text/markdown/code → CodeMirror+Yjs CollabEditor.
// - chooseOfficeEditor: .docx/.xlsx/.pptx → OnlyOffice bridge.
import { lazy, type ComponentType, type ForwardRefExoticComponent, type RefAttributes } from 'react'
import type { OfficeEditorHandle } from './office/OfficeEditor'
import type { WhiteboardEditorHandle } from './whiteboard/WhiteboardEditor'

const TextCollabEditor = lazy(() => import('./TextCollabEditor'))
// Cast through unknown so TypeScript understands the lazy-wrapped component
// still carries forwardRef's RefAttributes shape — chooseOfficeEditor's
// callers (FileEditorPage) need to attach a ref to drive save().
const OfficeEditor = lazy(() => import('./office/OfficeEditor')) as unknown as
  ForwardRefExoticComponent<OfficeEditorProps & RefAttributes<OfficeEditorHandle>>
const WhiteboardEditor = lazy(() => import('./whiteboard/WhiteboardEditor')) as unknown as
  ForwardRefExoticComponent<WhiteboardEditorProps & RefAttributes<WhiteboardEditorHandle>>

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
  'xml', 'svg', 'xsl', 'xsd',
  'bash', 'zsh', 'fish',
  'rb', 'rake', 'gemspec',
  'pl', 'pm',
  'ps1', 'psm1',
  'lua', 'swift',
])

const OFFICE_EXT = new Set(['docx', 'xlsx', 'pptx'])

const WHITEBOARD_EXT = new Set(['excalidraw'])

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
  /** Fires when inner.html intercepts Cmd/Ctrl+S inside the OO iframe. */
  onSaveShortcut?: () => void
}

export interface WhiteboardEditorProps {
  fileId: string
  filename: string
  collectionMaster: Uint8Array
  /** Decrypted .excalidraw JSON bytes if the file already exists. */
  initialBytes?: Uint8Array
}

export function chooseEditor(filename: string): ComponentType<CollabEditorProps> | null {
  const ext = filename.split('.').pop()?.toLowerCase() ?? ''
  if (TEXT_EXT.has(ext)) return TextCollabEditor
  return null
}

export function chooseOfficeEditor(filename: string):
  ForwardRefExoticComponent<OfficeEditorProps & RefAttributes<OfficeEditorHandle>> | null
{
  const ext = filename.split('.').pop()?.toLowerCase() ?? ''
  if (OFFICE_EXT.has(ext)) return OfficeEditor
  return null
}

export function chooseWhiteboardEditor(filename: string):
  ForwardRefExoticComponent<WhiteboardEditorProps & RefAttributes<WhiteboardEditorHandle>> | null
{
  const ext = filename.split('.').pop()?.toLowerCase() ?? ''
  if (WHITEBOARD_EXT.has(ext)) return WhiteboardEditor
  return null
}
