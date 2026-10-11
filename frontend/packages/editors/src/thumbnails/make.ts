import { THUMBNAIL_MAX_SIDE } from '@kutup/crypto/thumbnail'
import {
  DRIVE_PREVIEW_GENERATION_LIMITS_V1,
  MAX_PDF_BYTES,
  renderPdfFirstPageV1,
  renderTextPageV1,
} from '@kutup/files/mediaPreview'
import {
  thumbnailBudget,
  thumbnailsOfImage,
  thumbnailsOfPicture,
  thumbnailsOfVideo,
  toThumbnailImage,
  type MadeThumbnails,
} from '@kutup/files/thumbnails'
import { editorKindFor, extensionOf } from '@kutup/drive-core/editorKind'
import { fileKind } from '@kutup/drive-core/kinds'

export { thumbnailsOfPicture, type MadeThumbnails }

/** What a thumbnail is drawn from, or null when nothing can be. */
export type ThumbnailSource = 'image' | 'prose' | 'code' | 'whiteboard' | 'video' | 'pdf'

/** Only the start of a text file is drawn. */
const TEXT_BYTES = 64 * 1024

export function thumbnailSourceFor(name: string, mimeType?: string): ThumbnailSource | null {
  const kind = fileKind(name, mimeType)
  if (kind === 'image') return 'image'
  if (kind === 'whiteboard') return 'whiteboard'
  if (kind === 'video') return 'video'
  if (kind === 'pdf') return 'pdf'
  if (kind === 'note') return 'prose'
  if (kind === 'code' || editorKindFor(name) === 'text') return 'code'
  return null
}

/** A note or code file's page; `language` (a code file's extension) colours code. */
export async function thumbnailsOfText(text: string, mode: 'prose' | 'code', signal?: AbortSignal, language?: string): Promise<MadeThumbnails> {
  const sm = toThumbnailImage(
    await renderTextPageV1(text, mode, thumbnailBudget('sm'), DRIVE_PREVIEW_GENERATION_LIMITS_V1, signal, {}, language),
  )
  return sm ? { sm } : {}
}

/** A whiteboard, already exported as a picture (PNG) by Excalidraw. */
export function thumbnailsOfDrawing(png: Blob, signal?: AbortSignal): Promise<MadeThumbnails> {
  return thumbnailsOfPicture(png, true, signal)
}

type ExportToBlob = (options: {
  elements: readonly unknown[]
  appState: Record<string, unknown>
  files: Record<string, unknown>
  mimeType: string
  maxWidthOrHeight: number
}) => Promise<Blob>

/**
 * Draw a saved `.excalidraw` scene without the editor (backfill). Images in
 * the scene that are not embedded in it draw as Excalidraw's placeholder.
 */
export async function exportScene(json: string): Promise<Blob | null> {
  try {
    const scene = JSON.parse(json) as { elements?: unknown[]; appState?: Record<string, unknown>; files?: Record<string, unknown> }
    // Only the part used, typed here: Excalidraw's own typings reach into
    // packages the linter cannot resolve.
    const { exportToBlob } = (await import('@excalidraw/excalidraw')) as unknown as { exportToBlob: ExportToBlob }
    return await exportToBlob({
      elements: scene.elements ?? [],
      appState: { ...(scene.appState ?? {}), exportBackground: true, viewBackgroundColor: '#ffffff', exportWithDarkMode: false },
      files: scene.files ?? {},
      mimeType: 'image/png',
      maxWidthOrHeight: THUMBNAIL_MAX_SIDE.lg,
    })
  } catch {
    return null
  }
}

/** From the plaintext a client already has (an upload, a download). */
export async function thumbnailsOfFile(file: File, signal?: AbortSignal): Promise<MadeThumbnails> {
  const source = thumbnailSourceFor(file.name, file.type)
  switch (source) {
    case 'image':
      return thumbnailsOfImage(file, signal)
    case 'prose':
    case 'code':
      return thumbnailsOfText(await file.slice(0, TEXT_BYTES).text(), source, signal, source === 'code' ? extensionOf(file.name) : undefined)
    case 'whiteboard': {
      const png = await exportScene(await file.text())
      return png ? thumbnailsOfDrawing(png, signal) : {}
    }
    case 'pdf': {
      // Page one, large enough for Quick Look; the card scales it down.
      if (file.size > MAX_PDF_BYTES) return {}
      const png = await renderPdfFirstPageV1(await file.arrayBuffer(), THUMBNAIL_MAX_SIDE.lg, signal)
      return png ? thumbnailsOfPicture(png, true, signal) : {}
    }
    case 'video':
      return thumbnailsOfVideo(file, signal)
    default:
      return {}
  }
}
