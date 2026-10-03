import { enqueueThumbnail } from '@kutup/drive-core/thumbnailQueue'
import { removeThumbnails, storeThumbnails, type ThumbnailTarget } from '@kutup/drive-core/thumbnails'
import { thumbnailsOfPicture } from '@kutup/files/thumbnails'
import type { EffectiveMap } from '@kutup/map/config'
import type { Place } from '@kutup/map/list'
import { drawListPreview } from '@kutup/map/preview'

/** What a picture is drawn with, read when it is drawn. */
export interface ListLook {
  /** The map this person uses; null while maps are off (nothing is drawn). */
  map: EffectiveMap | null
  /** The list's colour in Maps, for its pins. */
  color: string
}

/**
 * Draws and stores the list's picture for `source` (a version id, or
 * `original`). Lists save a version only after a pause in editing, so every
 * save redraws: the picture is never behind the last saved places. A list
 * with no places has no picture (Drive shows its icon).
 */
export function drawListThumbnail(target: ThumbnailTarget, source: string, places: Place[], look: ListLook): void {
  if (places.length === 0) {
    enqueueThumbnail(target.fileId, () => removeThumbnails(target.fileId))
    return
  }
  const map = look.map
  if (!map) return
  const color = look.color
  enqueueThumbnail(target.fileId, async () => {
    const png = await drawListPreview(map, places, color)
    return png ? storeThumbnails(target, await thumbnailsOfPicture(png, true), source) : false
  })
}
