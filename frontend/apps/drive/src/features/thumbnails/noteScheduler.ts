import { thumbnailsOfText, thumbnailSourceFor } from './make'
import { enqueueThumbnail } from '@kutup/drive-core/thumbnailQueue'
import { storeThumbnails, type ThumbnailTarget } from '@kutup/drive-core/thumbnails'

/** Autosaves redraw at most this often; explicit saves always do. */
const MIN_INTERVAL_MS = 60_000

/**
 * Redraws a note's thumbnail as its versions are saved: at once for Save /
 * Save version, otherwise at most once a minute, from the text as it was
 * when that version was saved. `flush` draws any pending one (the editor is
 * closing) — the queue outlives the editor.
 */
export function noteThumbnailScheduler(target: ThumbnailTarget, filename: string) {
  const mode = thumbnailSourceFor(filename) === 'prose' ? 'prose' : 'code'
  let lastAt = 0
  let pending: { versionId: string; text: string } | null = null
  let timer: ReturnType<typeof setTimeout> | null = null

  const draw = (versionId: string, text: string) => {
    lastAt = Date.now()
    pending = null
    enqueueThumbnail(target.fileId, async () => storeThumbnails(target, await thumbnailsOfText(text, mode), versionId))
  }
  const clear = () => {
    if (timer) clearTimeout(timer)
    timer = null
  }

  return {
    saved(versionId: string, explicit: boolean, text: string) {
      const since = Date.now() - lastAt
      if (explicit || since >= MIN_INTERVAL_MS) {
        clear()
        draw(versionId, text)
        return
      }
      pending = { versionId, text }
      timer ??= setTimeout(() => {
        timer = null
        if (pending) draw(pending.versionId, pending.text)
      }, MIN_INTERVAL_MS - since)
    },
    flush() {
      clear()
      if (pending) draw(pending.versionId, pending.text)
    },
  }
}
