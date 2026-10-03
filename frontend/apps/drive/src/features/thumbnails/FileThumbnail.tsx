import { Play } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useRequiredSession } from '@kutup/session/store'
import { cn } from '@kutup/ui/lib/cn'
import { readFile } from '../drive/copy'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { currentContent } from '../editor/content'
import { KindIcon } from '../explorer/KindIcon'
import { thumbnailsOfFile, thumbnailSourceFor } from './make'
import { enqueueThumbnail, thumbnailInHand } from '@kutup/drive-core/thumbnailQueue'
import { storeThumbnails, thumbnailUrl } from '@kutup/drive-core/thumbnails'

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
function backfill(folder: Folder, file: DriveFile, userId: string): void {
  if (file.thumbnails.sm && !file.thumbnailStale) return
  if (thumbnailInHand(file.id)) return
  if (!file.fileKey || !file.name || folder.source === 'remote') return
  // New pictures are sealed only under the folder's current key; a file the
  // folder rotated past gets its picture when an editor re-keys it.
  if (file.keyEpoch !== folder.keyEpoch) return
  if (!(folder.canManage || file.uploaderUserId === userId)) return
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
  enqueueThumbnail(file.id, async () => {
    const content = await currentContent(folder, file)
    const blob = await readFile(folder, file)
    const made = await thumbnailsOfFile(new File([blob], name, { type: file.mimeType }))
    return storeThumbnails(
      { fileId: file.id, fileKey, keyGeneration: file.keyGeneration },
      made,
      content.kind === 'original' ? 'original' : (content.versionId ?? 'original'),
    )
  })
}

/**
 * A grid card's picture: the file's thumbnail once it is on screen, its kind
 * icon until then (and whenever there is none). Documents show from the top
 * of the page; pictures fill the frame.
 */
export function FileThumbnail({ folder, file }: { folder: Folder; file: DriveFile }) {
  const session = useRequiredSession()
  const box = useRef<HTMLDivElement>(null)
  const [visible, setVisible] = useState(false)
  const [url, setUrl] = useState<string | null>(null)

  useEffect(() => {
    const el = box.current
    if (!el || visible) return
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setVisible(true)
          observer.disconnect()
        }
      },
      { rootMargin: '200px' },
    )
    observer.observe(el)
    return () => observer.disconnect()
  }, [visible])

  const stamp = file.thumbnails.sm
  useEffect(() => {
    if (!visible) return
    let alive = true
    setUrl(null)
    void thumbnailUrl(file, 'sm').then((u) => alive && setUrl(u))
    backfill(folder, file, session.userId)
    return () => {
      alive = false
    }
    // The stored version (stamp) and staleness decide; the objects churn.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible, file.id, stamp, file.thumbnailStale])

  // Photos and maps fill the frame; pages show from the top; drawings show whole.
  const fit =
    file.kind === 'image' || file.kind === 'video' || file.kind === 'map'
      ? 'object-cover'
      : file.kind === 'whiteboard'
        ? 'bg-white object-contain p-1'
        : 'bg-white object-cover object-top'
  return (
    <div ref={box} className="absolute inset-0 flex items-center justify-center overflow-hidden rounded-lg">
      {url && file.kind === 'video' ? (
        // A frame alone reads as a photo; the badge says it plays.
        <span className="absolute z-10 flex size-10 items-center justify-center rounded-full bg-black/55 text-white shadow-sm">
          <Play className="size-5 translate-x-px fill-current" aria-hidden />
        </span>
      ) : null}
      {url ? (
        <img
          src={url}
          alt=""
          draggable={false}
          onError={() => setUrl(null)}
          className={cn('size-full', fit)}
        />
      ) : (
        <KindIcon kind={file.kind} className="size-14" />
      )}
    </div>
  )
}
