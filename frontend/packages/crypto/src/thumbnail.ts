// Drive thumbnails: a file's preview picture, sealed under its file key by
// the Rust core (kutup-crypto thumbnail.rs; docs/plans/drive-thumbnails.md).

import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

export type ThumbnailVariant = 'sm' | 'lg'

/** Longest side, per variant. */
export const THUMBNAIL_MAX_SIDE: Record<ThumbnailVariant, number> = { sm: 512, lg: 1920 }
/**
 * The largest encoded image a variant takes: its container cap less the
 * 13-byte header (the caps are whole padding blocks, so padding never pushes
 * an image of this size over).
 */
export const THUMBNAIL_MAX_IMAGE_BYTES: Record<ThumbnailVariant, number> = {
  sm: 64 * 1024 - 13,
  lg: 1024 * 1024 - 13,
}

export const THUMBNAIL_FORMAT = { jpeg: 1, webp: 2, png: 3 } as const
export type ThumbnailFormat = keyof typeof THUMBNAIL_FORMAT

const MIME: Record<ThumbnailFormat, string> = {
  jpeg: 'image/jpeg',
  webp: 'image/webp',
  png: 'image/png',
}

export interface ThumbnailImage {
  format: ThumbnailFormat
  width: number
  height: number
  image: Uint8Array
}

export interface ThumbnailContext {
  fileId: string
  /** The generation of the file key it is sealed under. */
  generation: number
  variant: ThumbnailVariant
}

export function thumbnailMimeType(format: ThumbnailFormat): string {
  return MIME[format]
}

export async function sealThumbnailV1(
  thumbnail: ThumbnailImage,
  fileKey: Uint8Array,
  context: ThumbnailContext,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  return fromBase64(
    module.sealThumbnail(
      toBase64(thumbnail.image),
      THUMBNAIL_FORMAT[thumbnail.format],
      thumbnail.width,
      thumbnail.height,
      context.variant,
      toBase64(fileKey),
      context.fileId,
      context.generation,
    ),
  )
}

export async function openThumbnailV1(
  envelope: Uint8Array,
  fileKey: Uint8Array,
  expected: ThumbnailContext,
): Promise<ThumbnailImage> {
  const module = await getCryptoWasm()
  const opened = module.openThumbnail(
    toBase64(envelope),
    expected.variant,
    toBase64(fileKey),
    expected.fileId,
    expected.generation,
  )
  const format = (Object.keys(THUMBNAIL_FORMAT) as ThumbnailFormat[]).find(
    (name) => THUMBNAIL_FORMAT[name] === opened.format,
  )
  if (!format) throw new Error('unknown thumbnail format')
  return { format, width: opened.width, height: opened.height, image: fromBase64(opened.image) }
}
