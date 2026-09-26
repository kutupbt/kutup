import {
  THUMBNAIL_MAX_IMAGE_BYTES,
  THUMBNAIL_MAX_SIDE,
  type ThumbnailImage,
  type ThumbnailVariant,
} from '@kutup/crypto/thumbnail'
import {
  captureVideoFrameV1,
  DRIVE_PREVIEW_GENERATION_LIMITS_V1,
  rasterizeImageFileV1,
  type RasterBudgetV1,
  type RasterResultV1,
} from './mediaPreview'

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

export async function thumbnailsOfImage(file: File, signal?: AbortSignal): Promise<MadeThumbnails> {
  const limits = DRIVE_PREVIEW_GENERATION_LIMITS_V1
  const sm = toThumbnailImage(await rasterizeImageFileV1(file, thumbnailBudget('sm'), limits, signal))
  if (!sm) return {}
  const lg = file.size > LARGE_IMAGE_BYTES ? toThumbnailImage(await rasterizeImageFileV1(file, thumbnailBudget('lg'), limits, signal)) : undefined
  return lg ? { sm, lg } : { sm }
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
