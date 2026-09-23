// The editor components, loaded on demand: CodeMirror, Excalidraw and the
// OnlyOffice bridge are each large and only one is ever needed per page.
// Which one a file gets is editorKindFor()'s decision (./editorKind).
import { lazy, type ForwardRefExoticComponent, type RefAttributes } from 'react'
import type { OfficeEditorHandle } from './office/OfficeEditor'
import type { WhiteboardEditorHandle } from './whiteboard/WhiteboardEditor'

export const TextCollabEditor = lazy(() => import('./text/TextCollabEditor'))
// Cast through unknown so TypeScript understands the lazy-wrapped component
// still carries forwardRef's RefAttributes shape — the file page attaches a
// ref to drive save().
export const OfficeEditor = lazy(() => import('./office/OfficeEditor')) as unknown as
  ForwardRefExoticComponent<OfficeEditorProps & RefAttributes<OfficeEditorHandle>>
export const WhiteboardEditor = lazy(() => import('./whiteboard/WhiteboardEditor')) as unknown as
  ForwardRefExoticComponent<WhiteboardEditorProps & RefAttributes<WhiteboardEditorHandle>>

export interface OfficeEditorProps {
  fileId: string
  collectionId: string
  filename: string
  collectionMaster: Uint8Array
  keyEpoch: number
  /** Decrypted file bytes (the OOXML blob). */
  initialBytes?: Uint8Array
  /** Fires when inner.html intercepts Cmd/Ctrl+S inside the OO iframe. */
  onSaveShortcut?: () => void
}

export interface WhiteboardEditorProps {
  fileId: string
  collectionId: string
  filename: string
  collectionMaster: Uint8Array
  keyEpoch: number
  /** Decrypted .excalidraw JSON bytes if the file already exists. */
  initialBytes?: Uint8Array
}
