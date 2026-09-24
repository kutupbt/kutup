import {
  THUMBNAIL_MAX_IMAGE_BYTES,
  THUMBNAIL_MAX_SIDE,
  type ThumbnailImage,
  type ThumbnailVariant,
} from '@kutup/crypto/thumbnail'
import {
  DRIVE_PREVIEW_GENERATION_LIMITS_V1,
  rasterizeImageFileV1,
  renderTextPageV1,
  type RasterBudgetV1,
  type RasterResultV1,
} from '@kutup/files/mediaPreview'
import { editorKindFor } from '../editor/editorKind'
import { fileKind } from '../explorer/kinds'

/** Thumbnails for one file, by variant (docs/plans/drive-thumbnails.md). */
export type MadeThumbnails = Partial<Record<ThumbnailVariant, ThumbnailImage>>

/** What a thumbnail is drawn from, or null when nothing can be. */
export type ThumbnailSource = 'image' | 'prose' | 'code' | 'whiteboard'

/** Images larger than this also get a large preview, for Quick Look. */
const LARGE_IMAGE_BYTES = 20 * 1024 * 1024
/** Only the start of a text file is drawn. */
const TEXT_BYTES = 64 * 1024

function budget(variant: ThumbnailVariant): RasterBudgetV1 {
  return {
    maxEdge: THUMBNAIL_MAX_SIDE[variant],
    maxOutputBytes: THUMBNAIL_MAX_IMAGE_BYTES[variant],
    // WebP where the browser can encode it; Safari cannot, so JPEG.
    outputTypes: ['image/webp', 'image/jpeg'],
  }
}

function toImage(result: RasterResultV1 | null): ThumbnailImage | undefined {
  if (!result) return undefined
  return {
    format: result.contentType === 'image/webp' ? 'webp' : 'jpeg',
    width: result.width,
    height: result.height,
    image: result.raster,
  }
}

export function thumbnailSourceFor(name: string, mimeType?: string): ThumbnailSource | null {
  const kind = fileKind(name, mimeType)
  if (kind === 'image') return 'image'
  if (kind === 'whiteboard') return 'whiteboard'
  if (kind === 'note') return 'prose'
  if (kind === 'code' || editorKindFor(name) === 'text') return 'code'
  return null
}

export async function thumbnailsOfImage(file: File, signal?: AbortSignal): Promise<MadeThumbnails> {
  const limits = DRIVE_PREVIEW_GENERATION_LIMITS_V1
  const sm = toImage(await rasterizeImageFileV1(file, budget('sm'), limits, signal))
  if (!sm) return {}
  const lg = file.size > LARGE_IMAGE_BYTES ? toImage(await rasterizeImageFileV1(file, budget('lg'), limits, signal)) : undefined
  return lg ? { sm, lg } : { sm }
}

export async function thumbnailsOfText(text: string, mode: 'prose' | 'code', signal?: AbortSignal): Promise<MadeThumbnails> {
  const sm = toImage(await renderTextPageV1(text, mode, budget('sm'), DRIVE_PREVIEW_GENERATION_LIMITS_V1, signal))
  return sm ? { sm } : {}
}

/** A whiteboard, already exported as a picture (PNG) by Excalidraw. */
export async function thumbnailsOfDrawing(png: Blob, signal?: AbortSignal): Promise<MadeThumbnails> {
  const file = new File([png], 'whiteboard.png', { type: 'image/png' })
  const limits = DRIVE_PREVIEW_GENERATION_LIMITS_V1
  const sm = toImage(await rasterizeImageFileV1(file, budget('sm'), limits, signal))
  const lg = toImage(await rasterizeImageFileV1(file, budget('lg'), limits, signal))
  return { ...(sm ? { sm } : {}), ...(lg ? { lg } : {}) }
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
      return thumbnailsOfText(await file.slice(0, TEXT_BYTES).text(), source, signal)
    case 'whiteboard': {
      const png = await exportScene(await file.text())
      return png ? thumbnailsOfDrawing(png, signal) : {}
    }
    default:
      return {}
  }
}
