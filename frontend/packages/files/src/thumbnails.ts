import {
  THUMBNAIL_MAX_IMAGE_BYTES,
  THUMBNAIL_MAX_SIDE,
  type ThumbnailImage,
  type ThumbnailVariant,
} from '@kutup/crypto/thumbnail'
import {
  captureVideoFrameV1,
  DRIVE_PREVIEW_GENERATION_LIMITS_V1,
  PHOTO_PREVIEW_GENERATION_LIMITS_V1,
  rasterizeImageFileV1,
  type RasterBudgetV1,
  type RasterResultV1,
} from './mediaPreview'
import { extractRawPreview, isRawName } from './media/raw'

// Pictures of photos and videos, as Drive and Photos draw them
// (docs/plans/drive-thumbnails.md): made on the device, from the plaintext.

/** Thumbnails for one file, by variant. */
export type MadeThumbnails = Partial<Record<ThumbnailVariant, ThumbnailImage>>

/** Images larger than this also get a large preview, for Quick Look and Photos' viewer. */
export const LARGE_IMAGE_BYTES = 20 * 1024 * 1024

export function thumbnailBudget(variant: ThumbnailVariant): RasterBudgetV1 {
  return {
    maxEdge: THUMBNAIL_MAX_SIDE[variant],
    maxOutputBytes: THUMBNAIL_MAX_IMAGE_BYTES[variant],
    // WebP where the browser can encode it; Safari cannot, so JPEG.
    outputTypes: ['image/webp', 'image/jpeg'],
  }
}

export function toThumbnailImage(result: RasterResultV1 | null): ThumbnailImage | undefined {
  if (!result) return undefined
  return {
    format: result.contentType === 'image/webp' ? 'webp' : 'jpeg',
    width: result.width,
    height: result.height,
    image: result.raster,
  }
}

/** HEIC/HEIF: only Safari draws them. */
export function isHeifName(name: string, type = ''): boolean {
  return /\.(heic|heif)$/i.test(name) || type === 'image/heic' || type === 'image/heif'
}

/**
 * What a picture is drawn from: the file itself, or a RAW file's embedded
 * JPEG (with the RAW's orientation). Null when a RAW has none.
 */
async function drawable(file: File): Promise<{ file: File; orientation?: number } | null> {
  if (!isRawName(file.name)) return { file }
  const preview = await extractRawPreview(file)
  if (!preview) return null
  return { file: new File([preview.jpeg], 'preview.jpg', { type: 'image/jpeg' }), orientation: preview.orientation }
}

export async function thumbnailsOfImage(file: File, signal?: AbortSignal): Promise<MadeThumbnails> {
  // Photos are drawn within the photo budget, in Drive as in Photos.
  const limits = PHOTO_PREVIEW_GENERATION_LIMITS_V1
  const source = await drawable(file)
  if (!source) return {}
  const budget = (variant: 'sm' | 'lg') => ({ ...thumbnailBudget(variant), ...(source.orientation ? { orientation: source.orientation } : {}) })
  const sm = toThumbnailImage(await rasterizeImageFileV1(source.file, budget('sm'), limits, signal))
  if (!sm) return {}
  // The large size where a viewer cannot show the original: large files,
  // and pictures most browsers cannot draw (HEIC, RAW).
  const large = file.size > LARGE_IMAGE_BYTES || isHeifName(file.name, file.type) || isRawName(file.name)
  const lg = large ? toThumbnailImage(await rasterizeImageFileV1(source.file, budget('lg'), limits, signal)) : undefined
  return lg ? { sm, lg } : { sm }
}

/**
 * A picture this browser cannot draw (HEIC outside Safari, RAW) as a JPEG it
 * can, up to 4096 pixels on its longest side, for the viewer. Null when it
 * cannot be made.
 */
export async function displayableImage(file: File, signal?: AbortSignal): Promise<Blob | null> {
  const source = await drawable(file)
  if (!source) return null
  const result = await rasterizeImageFileV1(
    source.file,
    {
      maxEdge: 4096,
      maxOutputBytes: 24 * 1024 * 1024,
      outputTypes: ['image/jpeg'],
      ...(source.orientation ? { orientation: source.orientation } : {}),
    },
    PHOTO_PREVIEW_GENERATION_LIMITS_V1,
    signal,
  )
  return result ? new Blob([result.raster as BlobPart], { type: result.contentType }) : null
}

/**
 * A picture drawn from a file (a whiteboard scene, a PDF page, a video
 * frame), as PNG, through the same bounded worker as photos. `large` also
 * makes the large size.
 */
export async function thumbnailsOfPicture(png: Blob, large: boolean, signal?: AbortSignal): Promise<MadeThumbnails> {
  const file = new File([png], 'preview.png', { type: 'image/png' })
  const limits = DRIVE_PREVIEW_GENERATION_LIMITS_V1
  const sm = toThumbnailImage(await rasterizeImageFileV1(file, thumbnailBudget('sm'), limits, signal))
  const lg = large ? toThumbnailImage(await rasterizeImageFileV1(file, thumbnailBudget('lg'), limits, signal)) : undefined
  return { ...(sm ? { sm } : {}), ...(lg ? { lg } : {}) }
}

/** A video's frame; the large size only where a viewer will not play it whole. */
export async function thumbnailsOfVideo(file: File, signal?: AbortSignal): Promise<MadeThumbnails> {
  const png = await captureVideoFrameV1(file, THUMBNAIL_MAX_SIDE.lg)
  return png ? thumbnailsOfPicture(png, file.size > LARGE_IMAGE_BYTES, signal) : {}
}
