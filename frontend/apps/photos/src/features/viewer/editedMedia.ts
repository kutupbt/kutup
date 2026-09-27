import type { MediaMetadataV1 } from '@kutup/crypto'

/**
 * The photo's new details from what the edit form holds, or null when the
 * form does not make sense. The date changes only when it was changed (a
 * photo whose date is unknown stays unknown otherwise); empty coordinates
 * remove the place, an empty caption removes the caption.
 */
export function editedMedia(
  media: MediaMetadataV1 | null,
  form: { when: string; offset: number; lat: string; lon: string; caption: string },
  dated: boolean,
  originalWhen: string,
  originalOffset: number | undefined,
): MediaMetadataV1 | null {
  const next: MediaMetadataV1 = { ...(media ?? {}) }
  const dateChanged = form.when !== originalWhen || (dated ? form.offset !== originalOffset : false)
  // A photo whose date is unknown keeps it unknown unless the date is set.
  if (form.when && dateChanged) {
    const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(form.when)
    if (!m) return null
    const utc = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]))
    next.takenAt = utc - form.offset * 60_000
    next.takenOffset = form.offset
    next.takenFrom = 'edited'
  }
  const lat = form.lat.trim()
  const lon = form.lon.trim()
  if (!lat && !lon) {
    delete next.lat
    delete next.lon
  } else {
    const a = Number(lat)
    const b = Number(lon)
    if (!Number.isFinite(a) || !Number.isFinite(b) || Math.abs(a) > 90 || Math.abs(b) > 180 || (a === 0 && b === 0)) return null
    next.lat = a
    next.lon = b
  }
  const caption = form.caption.trim()
  if (caption) next.caption = [...caption].slice(0, 2000).join('')
  else delete next.caption
  return next
}
