import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { currentContent, readFile } from '@kutup/editors/content'
import { thumbnailsOfFile, thumbnailSourceFor } from '@kutup/editors/thumbnails/make'
import { enqueueThumbnail, thumbnailInHand } from '@kutup/drive-core/thumbnailQueue'
import { storeThumbnails } from '@kutup/drive-core/thumbnails'

/** Backfill only what is cheap to draw. */
const BACKFILL_MAX_IMAGE_BYTES = 20 * 1024 * 1024
const BACKFILL_MAX_VIDEO_BYTES = 50 * 1024 * 1024
/** Each file's current content is tried once per tab. */
const tried = new Set<string>()

/**
 * Older files and stale thumbnails get redrawn in the background while they
 * are on screen — by someone who may write to the file (readers of shared
 * folders do not: it would charge their quota for the owner's files), never
 * on a data-saving connection, one at a time (docs/plans/drive-thumbnails.md).
 */
export function backfill(folder: Folder, file: DriveFile, accountId: string): void {
  if (file.thumbnails.sm && !file.thumbnailStale) return
  if (thumbnailInHand(file.id)) return
  if (!file.fileKey || !file.name || folder.source === 'remote') return
  // New pictures are sealed only under the folder's current key; a file the
  // folder rotated past gets its picture when an editor re-keys it.
  if (file.keyEpoch !== folder.keyEpoch) return
  if (!(folder.canManage || file.uploaderAccountId === accountId)) return
  const source = thumbnailSourceFor(file.name, file.mimeType)
  if (!source || ((source === 'image' || source === 'pdf') && file.size > BACKFILL_MAX_IMAGE_BYTES)) return
  // A video has to be downloaded whole to draw a frame: only small ones.
  if (source === 'video' && file.size > BACKFILL_MAX_VIDEO_BYTES) return
  const saveData = (navigator as Navigator & { connection?: { saveData?: boolean } }).connection?.saveData
  if (saveData) return
  const attempt = `${file.id}:${file.updatedAt}`
  if (tried.has(attempt)) return
  tried.add(attempt)
  const fileKey = file.fileKey
  const name = file.name
  // Bound to the content it is drawn from: the revision the metadata commits to.
  const revisionId = file.content?.revisionId
  if (!revisionId) return
  enqueueThumbnail(file.id, async () => {
    const content = await currentContent(folder, file)
    const blob = await readFile(folder, file)
    const made = await thumbnailsOfFile(new File([blob], name, { type: file.mimeType }))
    return storeThumbnails(
      { fileId: file.id, fileKey, keyGeneration: file.keyGeneration, revisionId },
      made,
      content.kind === 'original' ? 'original' : (content.versionId ?? 'original'),
    )
  })
}
