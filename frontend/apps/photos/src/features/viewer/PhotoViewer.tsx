import { Archive, ArchiveRestore, ChevronLeft, ChevronRight, Download, Eye, EyeOff, Heart, Info, MoreVertical, Trash2, X } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useTrashFile } from '@kutup/drive-core/mutations'
import { readOriginal } from '@kutup/drive-core/original'
import { useRequiredSession } from '@kutup/session/store'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@kutup/ui/components/dropdown-menu'
import { Button } from '@kutup/ui/components/button'
import { Spinner } from '@kutup/ui/components/states'
import { cn } from '@kutup/ui/lib/cn'
import { formatTaken } from '../library/format'
import { mayWrite } from '../library/catchUp'
import type { Photo } from '../library/library'
import { useLibraryContext } from '../library/libraryContext'
import type { MarkKind } from '../library/marks'
import { mayTrash } from '../timeline/mayTrash'
import { useThumbnail } from '../timeline/useThumbnail'
import { downloadPhoto } from '../timeline/downloads'
import { EditDetailsDialog } from './EditDetailsDialog'
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
  const small = useThumbnail(photo.file, 'sm')
  const large = useThumbnail(photo.file, 'lg')
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

  const session = useRequiredSession()
  const { marks } = useLibraryContext()
  const trash = useTrashFile()
  const [editing, setEditing] = useState(false)
  const [trashing, setTrashing] = useState(false)
  const favourite = marks.favourites.has(photo.id)
  const archived = marks.archived.has(photo.id)
  const hidden = marks.hidden.has(photo.id)
  /** The photo leaves this list: show the next one, or the one before, or close. */
  const leave = useCallback(() => {
    if (next) onNavigate(next)
    else if (prev) onNavigate(prev)
    else onClose()
  }, [next, prev, onNavigate, onClose])
  const markAndLeave = (kind: MarkKind, on: boolean) => {
    marks.set(kind, [photo.id], on).then(
      () => toast.success(t(kind === 'archived' ? (on ? 'selection.archived' : 'selection.unarchived') : on ? 'selection.hiddenDone' : 'selection.unhidden', { count: 1 })),
      () => toast.error(t('selection.markFailed')),
    )
    // Archiving or hiding takes it out of what is shown here.
    leave()
  }

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
            aria-label={favourite ? t('viewer.unfavourite') : t('viewer.favourite')}
            aria-pressed={favourite}
            onClick={() => void marks.set('favourites', [photo.id], !favourite).catch(() => toast.error(t('selection.markFailed')))}
          >
            <Heart className={favourite ? 'fill-current' : undefined} />
          </Button>
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
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="text-white hover:bg-white/15 hover:text-white" aria-label={t('selection.more')}>
                <MoreVertical />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onSelect={() => markAndLeave('archived', !archived)}>
                {archived ? <ArchiveRestore /> : <Archive />}
                {archived ? t('selection.unarchive') : t('selection.archive')}
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => markAndLeave('hidden', !hidden)}>
                {hidden ? <Eye /> : <EyeOff />}
                {hidden ? t('selection.unhide') : t('selection.hide')}
              </DropdownMenuItem>
              {mayTrash(photo, session.userId) ? (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onSelect={() => setTrashing(true)}>
                    <Trash2 />
                    {t('selection.trash')}
                  </DropdownMenuItem>
                </>
              ) : null}
            </DropdownMenuContent>
          </DropdownMenu>
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
      {info ? (
        <InfoPanel photo={photo} onClose={toggleInfo} onEdit={mayWrite(photo.folder, photo.file, session.userId) ? () => setEditing(true) : undefined} />
      ) : null}
      <EditDetailsDialog photo={photo} open={editing} onClose={() => setEditing(false)} />
      <ConfirmDestructive
        open={trashing}
        onOpenChange={setTrashing}
        title={t('selection.trashTitle', { count: 1 })}
        description={t('selection.trashDescription', { count: 1 })}
        submit={t('selection.trash')}
        pending={trash.isPending}
        errorFallback={t('selection.trashFailed', { count: 1 })}
        onConfirm={() => {
          trash.mutate(
            { folder: photo.folder, file: photo.file },
            {
              onSuccess: () => {
                setTrashing(false)
                leave()
                toast.success(t('selection.trashed', { count: 1 }))
              },
            },
          )
        }}
      />
    </div>
  )
}
