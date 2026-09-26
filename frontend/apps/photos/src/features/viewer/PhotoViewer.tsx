import { ChevronLeft, ChevronRight, Download, Info, X } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { readOriginal } from '@kutup/drive-core/original'
import { Button } from '@kutup/ui/components/button'
import { Spinner } from '@kutup/ui/components/states'
import { cn } from '@kutup/ui/lib/cn'
import { formatTaken } from '../library/format'
import type { Photo } from '../library/library'
import { useThumbnail } from '../timeline/useThumbnail'
import { downloadPhoto } from '../timeline/downloads'
import { InfoPanel } from './InfoPanel'

/** Originals up to this size open in the viewer; larger ones show their large thumbnail. */
const MAX_IMAGE_BYTES = 50 * 1024 * 1024
/** Videos play once downloaded (Drive's format cannot seek while streaming). */
const MAX_VIDEO_BYTES = 1024 * 1024 * 1024
/** Kinds every browser draws; others (HEIC, RAW, TIFF) are tried and may fall back. */
const INFO_KEY = 'kutup-photos-info'

// The last few originals, decrypted, for going back and forth. A download
// is shared by whoever wants it and stopped only once nobody has wanted it
// for a moment (a remount, as in development, keeps it going).
interface Loading {
  url: Promise<string>
  controller: AbortController
  users: number
  settled: boolean
  progress: Set<(read: number) => void>
}
const originals = new Map<string, Loading>()

function acquireOriginal(photo: Photo, onProgress: (read: number) => void): { url: Promise<string>; release: () => void } {
  const key = `${photo.id}:${photo.file.contentKeyGeneration}`
  let entry = originals.get(key)
  if (!entry) {
    const controller = new AbortController()
    const progress = new Set<(read: number) => void>()
    const created: Loading = {
      controller,
      users: 0,
      settled: false,
      progress,
      url: readOriginal(photo.folder, photo.file, controller.signal, (read) => progress.forEach((p) => p(read))).then((blob) =>
        URL.createObjectURL(blob),
      ),
    }
    created.url.then(
      () => {
        created.settled = true
      },
      () => {
        created.settled = true
        if (originals.get(key) === created) originals.delete(key)
      },
    )
    originals.set(key, created)
    entry = created
    while (originals.size > 4) {
      const [oldest, old] = originals.entries().next().value as [string, Loading]
      if (old.users > 0) break
      originals.delete(oldest)
      old.controller.abort()
      void old.url.then((u) => URL.revokeObjectURL(u)).catch(() => {})
    }
  }
  const held = entry
  held.users++
  held.progress.add(onProgress)
  return {
    url: held.url,
    release: () => {
      held.users--
      held.progress.delete(onProgress)
      setTimeout(() => {
        if (held.users === 0 && !held.settled) {
          held.controller.abort()
          if (originals.get(key) === held) originals.delete(key)
        }
      }, 0)
    },
  }
}

function readStoredInfo(): boolean {
  try {
    return localStorage.getItem(INFO_KEY) === '1'
  } catch {
    return false
  }
}

type Original = { state: 'loading'; read: number } | { state: 'ready'; url: string } | { state: 'unavailable' } | { state: 'failed' }

/** Open the photo's original (or not, when it is too large or cannot be drawn). */
function useOriginal(photo: Photo): Original {
  const tooLarge = photo.file.size > (photo.kind === 'video' ? MAX_VIDEO_BYTES : MAX_IMAGE_BYTES)
  const [original, setOriginal] = useState<Original>(tooLarge ? { state: 'unavailable' } : { state: 'loading', read: 0 })
  useEffect(() => {
    if (tooLarge) {
      setOriginal({ state: 'unavailable' })
      return
    }
    let alive = true
    setOriginal({ state: 'loading', read: 0 })
    const { url, release } = acquireOriginal(photo, (read) => alive && setOriginal({ state: 'loading', read }))
    url.then(
      (u) => alive && setOriginal({ state: 'ready', url: u }),
      () => alive && setOriginal({ state: 'failed' }),
    )
    return () => {
      alive = false
      release()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [photo.id, tooLarge])
  return original
}

function Picture({ photo }: { photo: Photo }) {
  const { t } = useTranslation()
  const small = useThumbnail(photo, 'sm')
  const large = useThumbnail(photo, 'lg')
  const original = useOriginal(photo)
  const [undrawable, setUndrawable] = useState(false)
  useEffect(() => setUndrawable(false), [photo.id])
  const preview = large ?? small

  if (photo.kind === 'video') {
    if (original.state === 'ready') {
      return (
        <video
          key={photo.id}
          src={original.url}
          controls
          autoPlay
          playsInline
          className="max-h-full max-w-full"
          aria-label={photo.file.name ?? ''}
        />
      )
    }
    return (
      <div className="relative flex max-h-full max-w-full items-center justify-center">
        {preview ? <img src={preview} alt="" className="max-h-[85svh] max-w-full object-contain opacity-60" /> : null}
        <div className="absolute flex flex-col items-center gap-2 rounded-lg bg-black/60 px-4 py-3 text-sm">
          {original.state === 'loading' ? (
            <>
              <Spinner label={t('viewer.loadingVideo')} className="text-white" />
              <span className="tabular-nums">{Math.round((original.read / Math.max(1, photo.file.size)) * 100)}%</span>
            </>
          ) : original.state === 'unavailable' ? (
            <span>{t('viewer.videoTooLarge')}</span>
          ) : (
            <span>{t('viewer.failed')}</span>
          )}
        </div>
      </div>
    )
  }

  const showOriginal = original.state === 'ready' && !undrawable
  return (
    <div className="relative flex size-full items-center justify-center">
      {!showOriginal && preview ? (
        <img src={preview} alt="" className="max-h-full max-w-full object-contain" draggable={false} />
      ) : null}
      {original.state === 'ready' && !undrawable ? (
        <img
          key={photo.id}
          src={original.url}
          alt={photo.file.name ?? ''}
          draggable={false}
          onError={() => setUndrawable(true)}
          className="max-h-full max-w-full object-contain"
        />
      ) : null}
      {original.state === 'loading' && !preview ? <Spinner label={t('viewer.loading')} className="text-white" /> : null}
      {undrawable || original.state === 'unavailable' || original.state === 'failed' ? (
        <p className="absolute bottom-4 rounded-md bg-black/60 px-3 py-1.5 text-xs text-white/85">
          {undrawable ? t('viewer.cannotDraw') : original.state === 'failed' ? t('viewer.failed') : t('viewer.showingPreview')}
        </p>
      ) : null}
    </div>
  )
}

interface Props {
  photos: readonly Photo[]
  index: number
  onNavigate: (photo: Photo) => void
  onClose: () => void
}

/** A photo or video full screen: arrows, swipes and keys go between them; `i` shows its details. */
export function PhotoViewer({ photos, index, onNavigate, onClose }: Props) {
  const { t, i18n } = useTranslation()
  const photo = photos[index]
  const [info, setInfo] = useState(readStoredInfo)
  const root = useRef<HTMLDivElement>(null)
  const swipe = useRef<{ x: number; y: number } | null>(null)
  const prev = index > 0 ? photos[index - 1] : undefined
  const next = index < photos.length - 1 ? photos[index + 1] : undefined

  const toggleInfo = useCallback(() => {
    setInfo((v) => {
      try {
        localStorage.setItem(INFO_KEY, v ? '0' : '1')
      } catch {
        // Remembering is a convenience.
      }
      return !v
    })
  }, [])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return
      if (e.key === 'Escape') onClose()
      else if (e.key === 'ArrowLeft' && prev) onNavigate(prev)
      else if (e.key === 'ArrowRight' && next) onNavigate(next)
      else if (e.key === 'i') toggleInfo()
      else return
      e.preventDefault()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [prev, next, onNavigate, onClose, toggleInfo])

  // The page behind stays where it was.
  useEffect(() => {
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    root.current?.focus()
    return () => {
      document.body.style.overflow = previous
    }
  }, [])

  const taken = formatTaken(photo, i18n.language)
  return (
    <div
      ref={root}
      role="dialog"
      aria-modal="true"
      aria-label={photo.file.name ?? ''}
      tabIndex={-1}
      className="fixed inset-0 z-50 flex bg-black text-white focus:outline-none"
    >
      <div
        className="relative flex min-w-0 flex-1 items-center justify-center"
        onPointerDown={(e) => {
          if (e.pointerType !== 'mouse') swipe.current = { x: e.clientX, y: e.clientY }
        }}
        onPointerUp={(e) => {
          const start = swipe.current
          swipe.current = null
          if (!start) return
          const dx = e.clientX - start.x
          if (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(e.clientY - start.y) * 1.5) {
            if (dx < 0 && next) onNavigate(next)
            if (dx > 0 && prev) onNavigate(prev)
          }
        }}
      >
        <div className="absolute inset-x-0 top-0 z-10 flex items-center gap-2 bg-gradient-to-b from-black/70 to-transparent px-2 py-2 sm:px-4">
          <Button variant="ghost" size="icon" className="text-white hover:bg-white/15 hover:text-white" aria-label={t('common.close')} onClick={onClose}>
            <X />
          </Button>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">{photo.dated ? taken.date : (photo.file.name ?? '')}</p>
            <p className="truncate text-xs text-white/70">{photo.dated ? `${taken.time}${taken.zone ? ` · ${taken.zone}` : ''}` : t('viewer.dateUnknown')}</p>
          </div>
          <Button
            variant="ghost"
            size="icon"
            className="text-white hover:bg-white/15 hover:text-white"
            aria-label={t('viewer.download')}
            onClick={() =>
              void downloadPhoto(photo).catch((error: unknown) => {
                if (!(error instanceof DOMException && error.name === 'AbortError')) toast.error(t('selection.downloadFailed'))
              })
            }
          >
            <Download />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className={cn('text-white hover:bg-white/15 hover:text-white', info && 'bg-white/15')}
            aria-label={t('viewer.info')}
            aria-pressed={info}
            onClick={toggleInfo}
          >
            <Info />
          </Button>
        </div>

        <div className="flex size-full items-center justify-center px-2 pb-4 pt-16 sm:px-16">
          <Picture key={photo.id} photo={photo} />
        </div>

        {prev ? (
          <button
            type="button"
            aria-label={t('viewer.previous')}
            onClick={() => onNavigate(prev)}
            className="absolute left-2 top-1/2 hidden size-11 -translate-y-1/2 items-center justify-center rounded-full bg-black/40 text-white hover:bg-black/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white sm:flex"
          >
            <ChevronLeft />
          </button>
        ) : null}
        {next ? (
          <button
            type="button"
            aria-label={t('viewer.next')}
            onClick={() => onNavigate(next)}
            className="absolute right-2 top-1/2 hidden size-11 -translate-y-1/2 items-center justify-center rounded-full bg-black/40 text-white hover:bg-black/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white sm:flex"
          >
            <ChevronRight />
          </button>
        ) : null}
      </div>
      {info ? <InfoPanel photo={photo} onClose={toggleInfo} /> : null}
    </div>
  )
}
