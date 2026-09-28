import { enqueueThumbnail } from '@kutup/drive-core/thumbnailQueue'
import { storeThumbnails, type ThumbnailTarget } from '@kutup/drive-core/thumbnails'
import { thumbnailsOfPicture } from '@kutup/files/thumbnails'
import type { EffectiveMap } from '@kutup/map/config'
import type { Place } from '@kutup/map/list'
import { drawListPreview } from '@kutup/map/preview'

/** Autosaves redraw at most this often; explicit saves always do. */
const MIN_INTERVAL_MS = 60_000

/** What a picture is drawn with, read when it is drawn. */
export interface ListLook {
  /** The map this person uses; null while maps are off (nothing is drawn). */
  map: EffectiveMap | null
  /** The list's colour in Maps, for its pins. */
  color: string
}

/** Draws and stores the list's picture for `source` (a version id, or `original`). */
export function drawListThumbnail(target: ThumbnailTarget, source: string, places: Place[], look: ListLook): void {
  const map = look.map
  if (!map || places.length === 0) return
  const color = look.color
  enqueueThumbnail(target.fileId, async () => {
    const png = await drawListPreview(map, places, color)
    return png ? storeThumbnails(target, await thumbnailsOfPicture(png, true), source) : false
  })
}

/**
 * Redraws a place list's Drive picture as its versions are saved: at once
 * for an explicit save, otherwise at most once a minute, from the places as
 * they were when that version was saved. `flush` draws any pending one (the
 * list is closing); the queue outlives the list.
 */
export function listThumbnailScheduler(target: ThumbnailTarget, look: () => ListLook) {
  let lastAt = 0
  let pending: { versionId: string; places: Place[] } | null = null
  let timer: ReturnType<typeof setTimeout> | null = null

  const draw = (versionId: string, places: Place[]) => {
    lastAt = Date.now()
    pending = null
    drawListThumbnail(target, versionId, places, look())
  }
  const clear = () => {
    if (timer) clearTimeout(timer)
    timer = null
  }

  return {
    saved(versionId: string, explicit: boolean, places: Place[]) {
      const since = Date.now() - lastAt
      if (explicit || since >= MIN_INTERVAL_MS) {
        clear()
        draw(versionId, places)
        return
      }
      pending = { versionId, places }
      timer ??= setTimeout(() => {
        timer = null
        if (pending) draw(pending.versionId, pending.places)
      }, MIN_INTERVAL_MS - since)
    },
    flush() {
      clear()
      if (pending) draw(pending.versionId, pending.places)
    },
  }
}
