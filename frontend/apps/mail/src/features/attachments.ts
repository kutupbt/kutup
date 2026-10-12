// A message's files: what each previews as, downloading one, zipping all
// (Proton's AttachmentPreview and Download all).
import { zipSync } from 'fflate'
import type { ParsedAttachment } from '@kutup/mail-core/mime'

/** What a file previews as, as Proton's AttachmentPreview: images, PDFs, media and plain text. */
export type PreviewKind = 'image' | 'pdf' | 'video' | 'audio' | 'text'

const IMAGES = new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp', 'image/bmp', 'image/apng', 'image/svg+xml', 'image/x-icon', 'image/vnd.microsoft.icon'])
/** Text shown in a preview: the first part of a long file. */
export const TEXT_PREVIEW_BYTES = 1024 * 1024

export function previewKind(file: Pick<ParsedAttachment, 'mimeType' | 'filename'>): PreviewKind | null {
  const type = file.mimeType.toLowerCase()
  if (IMAGES.has(type)) return 'image'
  if (type === 'application/pdf' || type === 'application/x-pdf') return 'pdf'
  if (type.startsWith('video/')) return 'video'
  if (type.startsWith('audio/')) return 'audio'
  if (type.startsWith('text/') && type !== 'text/html') return 'text'
  return null
}

export function download(name: string, type: string, bytes: Uint8Array) {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = name
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 30_000)
}

/** Every file in one zip, each name once (Proton's `Attachments-<subject>.zip`). */
export function zipAttachments(files: Pick<ParsedAttachment, 'filename' | 'content'>[], unnamed: string): Uint8Array {
  const used = new Map<string, number>()
  const entries: Record<string, Uint8Array> = {}
  for (const file of files) {
    const base = (file.filename || unnamed).replace(/[/\\]/g, '_')
    const seen = used.get(base) ?? 0
    used.set(base, seen + 1)
    const dot = base.lastIndexOf('.')
    const name = seen === 0 ? base : dot > 0 ? `${base.slice(0, dot)} (${seen})${base.slice(dot)}` : `${base} (${seen})`
    entries[name] = file.content
  }
  return zipSync(entries, { level: 0 })
}

/** Proton's list never shows calendar invites or keys as files (`filterAttachmentToPreview`). */
const NOT_LISTED_TYPES = new Set(['text/calendar', 'application/ics', 'application/pgp-keys'])

/** The files a list row shows, of those its message (or conversation) has. */
export function listedAttachments<T extends { name: string; type: string }>(files: T[]): T[] {
  return files.filter((file) => !NOT_LISTED_TYPES.has(file.type.toLowerCase()) && !/\.(ics|asc|key|pub)$/i.test(file.name))
}

/** How many chips a row shows before "+N" (Proton's 3 in the row layout, 2 in columns). */
export const chipsShown = (layout: 'column' | 'row') => (layout === 'row' ? 3 : 2)
