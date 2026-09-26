// What a photo says about itself (docs/plans/photos.md), from its EXIF, XMP
// and IPTC tags, read with ExifReader as Ente and Proton do. The tag choices
// follow Ente's (`web/packages/gallery/services/exif.ts`).

import type ExifReaderType from 'exifreader'
import { parseCameraDate, type TakenDate } from './dates'

export interface ImageFacts {
  taken?: TakenDate
  lat?: number
  lon?: number
  width?: number
  height?: number
  camera?: string
}

type Tags = ExifReaderType.ExpandedTags

/** Photos are read whole up to this size; larger ones from their start. */
const WHOLE_BYTES = 64 * 1024 * 1024
const HEAD_BYTES = 8 * 1024 * 1024

function first(tag: { value?: unknown } | undefined): string | undefined {
  const value = tag?.value
  if (Array.isArray(value)) return typeof value[0] === 'string' ? value[0] : undefined
  return typeof value === 'string' ? value : undefined
}

function xmpText(tag: { value?: unknown } | undefined): string | undefined {
  return typeof tag?.value === 'string' ? tag.value : undefined
}

function takenFrom(tags: Tags): TakenDate | undefined {
  const exif = tags.exif
  const xmp = tags.xmp as Record<string, { value?: unknown }> | undefined
  const iptc = tags.iptc as Record<string, { description?: string }> | undefined
  const fromExif = (date?: { value?: unknown }, sub?: { value?: unknown }, zone?: { value?: unknown }) => {
    const text = first(date)
    return text ? parseCameraDate(text, first(sub), first(zone)) : undefined
  }
  const fromXmp = (name: string) => {
    const text = xmpText(xmp?.[name])
    return text ? parseCameraDate(text) : undefined
  }
  const fromIptc = (date: string, time: string) => {
    const d = iptc?.[date]?.description
    if (!d) return undefined
    const t = iptc?.[time]?.description
    return parseCameraDate(t ? `${d}T${t}` : d)
  }
  return (
    fromXmp('DateTimeOriginal') ??
    fromIptc('Date Created', 'Time Created') ??
    fromExif(exif?.DateTimeOriginal, exif?.SubSecTimeOriginal, exif?.OffsetTimeOriginal) ??
    fromXmp('DateCreated') ??
    fromXmp('DateTimeDigitized') ??
    fromIptc('Digital Creation Date', 'Digital Creation Time') ??
    fromExif(exif?.DateTimeDigitized, exif?.SubSecTimeDigitized, exif?.OffsetTimeDigitized) ??
    fromXmp('CreateDate') ??
    fromXmp('DateTime') ??
    fromExif(exif?.DateTime, exif?.SubSecTime, exif?.OffsetTime) ??
    fromXmp('ModifyDate')
  )
}

function dimensions(tags: Tags): { width: number; height: number } | undefined {
  const pair = (w: unknown, h: unknown) =>
    typeof w === 'number' && typeof h === 'number' && w > 0 && h > 0 ? { width: Math.round(w), height: Math.round(h) } : undefined
  const orientation = tags.exif?.Orientation?.value
  const turned = typeof orientation === 'number' && orientation >= 5 && orientation <= 8
  const size =
    pair(tags.file?.['Image Width']?.value, tags.file?.['Image Height']?.value) ??
    pair(tags.pngFile?.['Image Width']?.value, tags.pngFile?.['Image Height']?.value) ??
    pair(tags.gif?.['Image Width']?.value, tags.gif?.['Image Height']?.value) ??
    pair(tags.riff?.ImageWidth?.value, tags.riff?.ImageHeight?.value) ??
    pair(tags.exif?.PixelXDimension?.value, tags.exif?.PixelYDimension?.value) ??
    pair(tags.exif?.ImageWidth?.value, tags.exif?.ImageLength?.value)
  if (!size) return undefined
  return turned ? { width: size.height, height: size.width } : size
}

function camera(tags: Tags): string | undefined {
  const make = tags.exif?.Make?.description?.trim() ?? ''
  const model = tags.exif?.Model?.description?.trim() ?? ''
  // "Apple iPhone 15", but "Canon EOS R5" not "Canon Canon EOS R5".
  const name = model.toLowerCase().startsWith(make.toLowerCase()) ? model : `${make} ${model}`.trim()
  return name ? [...name].slice(0, 100).join('') : undefined
}

/** A photo's facts. Unknown fields are left out; unreadable files give {}. */
export async function readImageFacts(file: Blob): Promise<ImageFacts> {
  const { default: ExifReader } = await import('exifreader')
  const bytes = await file.slice(0, file.size <= WHOLE_BYTES ? file.size : HEAD_BYTES).arrayBuffer()
  let tags: Tags
  try {
    tags = ExifReader.load(bytes, { expanded: true, includeUnknown: false })
  } catch {
    return {}
  }
  const facts: ImageFacts = {}
  const taken = takenFrom(tags)
  if (taken) facts.taken = taken
  const lat = tags.gps?.Latitude
  const lon = tags.gps?.Longitude
  if (typeof lat === 'number' && typeof lon === 'number' && Number.isFinite(lat) && Number.isFinite(lon)
    && Math.abs(lat) <= 90 && Math.abs(lon) <= 180 && !(lat === 0 && lon === 0)) {
    facts.lat = lat
    facts.lon = lon
  }
  const size = dimensions(tags)
  if (size) Object.assign(facts, size)
  const name = camera(tags)
  if (name) facts.camera = name
  return facts
}
