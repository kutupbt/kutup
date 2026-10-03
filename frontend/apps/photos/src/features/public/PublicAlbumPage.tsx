import { useQuery } from '@tanstack/react-query'
import { Aperture, ChevronLeft, ChevronRight, Download, Play, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { isHeifName, displayableImage } from '@kutup/files/thumbnails'
import { isRawName } from '@kutup/files/media/raw'
import { Alert } from '@kutup/ui/components/alert'
import { KutupLogo } from '@kutup/ui/components/brand'
import { Button } from '@kutup/ui/components/button'
import { LoadingPanel, Spinner } from '@kutup/ui/components/states'
import { ThemeToggle } from '@kutup/ui/components/theme-toggle'
import { formatDuration, formatTaken } from '../library/format'
import { loadPublicAlbum, PublicAlbumError, publicThumbnail, readPublicOriginal, type PublicPhoto } from './publicAlbum'

const MAX_ORIGINAL_BYTES = 50 * 1024 * 1024

function useLinkThumbnail(token: string, photo: PublicPhoto, variant: 'sm' | 'lg'): string | null {
  const [url, setUrl] = useState<string | null>(null)
  useEffect(() => {
    let alive = true
    setUrl(null)
    void publicThumbnail(token, photo, variant).then((u) => alive && setUrl(u))
    return () => {
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, photo.id, variant])
  return url
}

function Tile({ token, photo, onOpen }: { token: string; photo: PublicPhoto; onOpen: () => void }) {
  const { i18n } = useTranslation()
  const url = useLinkThumbnail(token, photo, 'sm')
  const taken = formatTaken(photo, i18n.language)
  return (
    <button
      type="button"
      onClick={onOpen}
      aria-label={`${photo.file.name ?? ''}, ${taken.date} ${taken.time}`}
      className="relative aspect-square overflow-hidden bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
    >
      {url ? <img src={url} alt="" className="size-full object-cover" draggable={false} /> : null}
      {photo.live ? (
        <Aperture className="absolute right-1.5 top-1.5 size-4 text-white drop-shadow" aria-hidden />
      ) : null}
      {photo.kind === 'video' ? (
        <span className="absolute bottom-1.5 right-1.5 flex items-center gap-1 rounded bg-black/60 px-1.5 py-0.5 text-[11px] font-medium text-white">
          <Play className="size-3 fill-current" aria-hidden />
          {photo.media?.durationMs !== undefined ? formatDuration(photo.media.durationMs) : null}
        </span>
      ) : null}
    </button>
  )
}

/** The picture or video, full screen: the original when the browser can show it. */
function Shown({ token, photo }: { token: string; photo: PublicPhoto }) {
  const { t } = useTranslation()
  const large = useLinkThumbnail(token, photo, 'lg')
  const small = useLinkThumbnail(token, photo, 'sm')
  const preview = large ?? small
  const [url, setUrl] = useState<string | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    if (photo.file.size > MAX_ORIGINAL_BYTES && photo.kind === 'image') return
    const controller = new AbortController()
    let made: string | null = null
    setUrl(null)
    setFailed(false)
    void readPublicOriginal(token, photo, controller.signal)
      .then(async (blob) => {
        const name = photo.file.name ?? ''
        // HEIC outside Safari, and RAW, are converted here as in the app.
        const needsConversion = photo.kind === 'image' && (isRawName(name) || (isHeifName(name, photo.file.mimeType) && !CSS.supports('-webkit-touch-callout', 'none')))
        const shown = needsConversion ? await displayableImage(new File([blob], name, { type: photo.file.mimeType })) : blob
        if (!shown) return
        made = URL.createObjectURL(shown)
        setUrl(made)
      })
      .catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === 'AbortError')) setFailed(true)
      })
    return () => {
      controller.abort()
      if (made) URL.revokeObjectURL(made)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, photo.id])

  if (photo.kind === 'video') {
    return url ? (
      <video src={url} controls autoPlay playsInline className="max-h-full max-w-full" aria-label={photo.file.name ?? ''} />
    ) : (
      <div className="flex flex-col items-center gap-2 text-sm">
        {preview ? <img src={preview} alt="" className="max-h-[70svh] max-w-full object-contain opacity-60" /> : null}
        {failed ? <span>{t('viewer.failed')}</span> : <Spinner label={t('viewer.loadingVideo')} className="text-white" />}
      </div>
    )
  }
  const src = url ?? preview
  return src ? (
    <img src={src} alt={url ? (photo.file.name ?? '') : ''} className="max-h-full max-w-full object-contain" draggable={false} onError={() => setUrl(null)} />
  ) : (
    <Spinner label={t('viewer.loading')} className="text-white" />
  )
}

async function saveOriginal(token: string, photo: PublicPhoto): Promise<void> {
  const blob = await readPublicOriginal(token, photo)
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = photo.file.name ?? 'photo'
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 30_000)
}

function Viewer({ token, photos, index, onIndex, onClose }: { token: string; photos: PublicPhoto[]; index: number; onIndex: (i: number) => void; onClose: () => void }) {
  const { t, i18n } = useTranslation()
  const photo = photos[index]
  const taken = formatTaken(photo, i18n.language)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
      else if (e.key === 'ArrowLeft' && index > 0) onIndex(index - 1)
      else if (e.key === 'ArrowRight' && index < photos.length - 1) onIndex(index + 1)
    }
    window.addEventListener('keydown', onKey)
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      window.removeEventListener('keydown', onKey)
      document.body.style.overflow = previous
    }
  }, [index, photos.length, onIndex, onClose])
  return (
    <div role="dialog" aria-modal="true" aria-label={photo.file.name ?? ''} className="fixed inset-0 z-50 flex flex-col bg-black text-white">
      <div className="flex items-center gap-2 px-2 py-2 sm:px-4">
        <Button variant="ghost" size="icon" className="text-white hover:bg-white/15 hover:text-white" aria-label={t('common.close')} onClick={onClose}>
          <X />
        </Button>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">{photo.dated ? taken.date : (photo.file.name ?? '')}</p>
          {photo.dated ? <p className="truncate text-xs text-white/70">{`${taken.time}${taken.zone ? ` · ${taken.zone}` : ''}`}</p> : null}
        </div>
        <Button
          variant="ghost"
          size="icon"
          className="text-white hover:bg-white/15 hover:text-white"
          aria-label={t('viewer.download')}
          onClick={() => void saveOriginal(token, photo).catch(() => toast.error(t('selection.downloadFailed')))}
        >
          <Download />
        </Button>
      </div>
      <div className="relative flex min-h-0 flex-1 items-center justify-center px-2 pb-4 sm:px-16">
        <Shown key={photo.id} token={token} photo={photo} />
        {index > 0 ? (
          <button type="button" aria-label={t('viewer.previous')} onClick={() => onIndex(index - 1)} className="absolute left-2 top-1/2 flex size-11 -translate-y-1/2 items-center justify-center rounded-full bg-black/40 hover:bg-black/60">
            <ChevronLeft />
          </button>
        ) : null}
        {index < photos.length - 1 ? (
          <button type="button" aria-label={t('viewer.next')} onClick={() => onIndex(index + 1)} className="absolute right-2 top-1/2 flex size-11 -translate-y-1/2 items-center justify-center rounded-full bg-black/40 hover:bg-black/60">
            <ChevronRight />
          </button>
        ) : null}
      </div>
    </div>
  )
}

/**
 * An album through its public link: no account needed. The link's key is in
 * the address fragment, which never reaches the server; the page opens the
 * album and its photos here.
 */
export function PublicAlbumPage() {
  const { t } = useTranslation()
  const { token = '' } = useParams()
  const album = useQuery({ queryKey: ['public-album', token], queryFn: () => loadPublicAlbum(token), retry: false })
  const [open, setOpen] = useState<number | null>(null)
  const failure = album.error instanceof PublicAlbumError ? album.error.failure : album.isError ? 'other' : null

  return (
    <div className="min-h-svh bg-background">
      <header className="flex h-14 items-center gap-3 border-b border-border px-4 md:px-8">
        <KutupLogo size={22} />
        <span className="font-display font-semibold">{t('apps.photos')}</span>
        <div className="ml-auto">
          <ThemeToggle onChrome={false} />
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-2 py-6 md:px-8">
        {album.isPending ? <LoadingPanel label={t('public.loading')} /> : null}
        {failure ? (
          <div className="px-2">
            <Alert variant="error" title={t('public.failedTitle')}>
              {t(`public.failure.${failure}`)}
            </Alert>
          </div>
        ) : null}
        {album.data ? (
          <>
            <div className="mb-4 flex items-baseline justify-between gap-4 px-2">
              <h1 className="min-w-0 truncate font-display text-2xl font-semibold tracking-tight">{album.data.name}</h1>
              <p className="shrink-0 text-sm text-muted-foreground">{t('timeline.count', { count: album.data.photos.length })}</p>
            </div>
            <p className="mb-4 px-2 text-sm text-muted-foreground">{t('public.note')}</p>
            <div className="grid grid-cols-3 gap-0.5 sm:grid-cols-4 lg:grid-cols-6">
              {album.data.photos.map((photo, i) => (
                <Tile key={photo.id} token={token} photo={photo} onOpen={() => setOpen(i)} />
              ))}
            </div>
            {open !== null && album.data.photos[open] ? (
              <Viewer token={token} photos={album.data.photos} index={open} onIndex={setOpen} onClose={() => setOpen(null)} />
            ) : null}
          </>
        ) : null}
      </main>
    </div>
  )
}
