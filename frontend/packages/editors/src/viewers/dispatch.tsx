// Maps a filename's extension to a read-only viewer component. Distinct from
// the collab editor dispatch (which only matches text/markdown/code today).
// FileEditorPage tries chooseEditor first, then chooseViewer, then falls back
// to the download-only details panel.
import { lazy, type ComponentType } from 'react'

const ImageViewer = lazy(() => import('./ImageViewer'))
const PdfViewer = lazy(() => import('./PdfViewer'))
const MediaViewer = lazy(() => import('./MediaViewer'))

const IMAGE_EXT = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg', 'avif', 'heic'])
const PDF_EXT = new Set(['pdf'])
const VIDEO_EXT = new Set(['mp4', 'webm', 'mov', 'mkv', 'avi'])
const AUDIO_EXT = new Set(['mp3', 'wav', 'flac', 'ogg', 'm4a', 'aac'])

const MIME_BY_EXT: Record<string, string> = {
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
  webp: 'image/webp', bmp: 'image/bmp', svg: 'image/svg+xml', avif: 'image/avif',
  heic: 'image/heic',
  pdf: 'application/pdf',
  mp4: 'video/mp4', webm: 'video/webm', mov: 'video/quicktime', mkv: 'video/x-matroska',
  avi: 'video/x-msvideo',
  mp3: 'audio/mpeg', wav: 'audio/wav', flac: 'audio/flac', ogg: 'audio/ogg',
  m4a: 'audio/mp4', aac: 'audio/aac',
}

export interface ViewerProps {
  filename: string
  /** Object URL backed by a Blob made from the decrypted bytes. The viewer
   *  must NOT keep this URL alive past the parent's unmount; the parent
   *  revokes it. */
  blobUrl: string
  /** Best-guess mime type derived from the extension. */
  mimeType: string
}

export type ViewerKind = 'image' | 'pdf' | 'video' | 'audio'

export function chooseViewer(filename: string): {
  Component: ComponentType<ViewerProps>
  kind: ViewerKind
  mimeType: string
} | null {
  const ext = filename.split('.').pop()?.toLowerCase() ?? ''
  const mimeType = MIME_BY_EXT[ext] ?? 'application/octet-stream'
  if (IMAGE_EXT.has(ext)) return { Component: ImageViewer, kind: 'image', mimeType }
  if (PDF_EXT.has(ext))   return { Component: PdfViewer,   kind: 'pdf',   mimeType }
  if (VIDEO_EXT.has(ext)) return { Component: MediaViewer, kind: 'video', mimeType }
  if (AUDIO_EXT.has(ext)) return { Component: MediaViewer, kind: 'audio', mimeType }
  return null
}
