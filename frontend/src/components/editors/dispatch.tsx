// Maps a filename's extension to a collab-editor component, or null for fall-through
// to the existing preview/download UI.
import { lazy, type ComponentType } from 'react'

const TextCollabEditor = lazy(() => import('./TextCollabEditor'))

const TEXT_EXT = new Set([
  'md', 'markdown', 'txt',
  'go', 'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx',
  'py', 'rs', 'json', 'yaml', 'yml',
  'html', 'htm', 'css', 'toml', 'sh', 'sql',
  'dockerfile', 'nix',
])

export interface CollabEditorProps {
  fileId: string
  filename: string
  collectionMaster: Uint8Array
  /** Optional plaintext seed for cold-start (no Yjs snapshot yet). */
  initialContent?: string
}

export function chooseEditor(filename: string): ComponentType<CollabEditorProps> | null {
  const ext = filename.split('.').pop()?.toLowerCase() ?? ''
  if (TEXT_EXT.has(ext)) return TextCollabEditor
  return null
}
