import { Play } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { cn } from '@kutup/ui/lib/cn'
import { KindIcon } from '@kutup/drive-ui/KindIcon'
import { useDriveSource } from '@kutup/drive-source/context'
import type { FileView, FolderView } from '@kutup/drive-source/source'

/**
 * A grid card's picture: the file's thumbnail once it is on screen, its kind
 * icon until then (and whenever there is none). Documents show from the top
 * of the page; pictures fill the frame.
 */
export function FileThumbnail({ folder, file }: { folder: FolderView; file: FileView }) {
  const source = useDriveSource()
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

  const stamp = source.thumbnailStamp(file)
  useEffect(() => {
    if (!visible) return
    let alive = true
    setUrl(null)
    void source.thumbnail(folder, file, 'sm').then((u) => alive && setUrl(u))
    return () => {
      alive = false
    }
    // The stamp says when the picture changed; the objects churn.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible, file.id, stamp])

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
