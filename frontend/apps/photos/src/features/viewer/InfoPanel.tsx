import { ExternalLink, MapPin, Pencil, X } from 'lucide-react'
import { lazy, Suspense, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import type { Folder } from '@kutup/drive-core/model'
import { appUrl } from '@kutup/session/apps'
import { Button } from '@kutup/ui/components/button'
import { formatBytes } from '@kutup/ui/lib/format'
import { formatDuration, formatTaken } from '../library/format'
import type { Photo } from '../library/library'

const MapView = lazy(() => import('@kutup/map/MapView').then((m) => ({ default: m.MapView })))

/** Where a folder opens in Drive. */
function driveFolderUrl(folder: Folder): string {
  if (folder.isRoot) return appUrl('drive', '/')
  if (folder.source === 'remote' && folder.remoteShareId) return appUrl('drive', `/remote/${folder.remoteShareId}`)
  return appUrl('drive', `/folders/${folder.id}`)
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-0.5">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="break-words text-sm">{children}</dd>
    </div>
  )
}

/**
 * A photo's details: when (with the time zone it was taken in), where (a
 * small map, drawn on this device from the photo's encrypted details), the
 * camera, its size, and the Drive folder it is in.
 */
export function InfoPanel({ photo, onClose, onEdit }: { photo: Photo; onClose: () => void; onEdit?: () => void }) {
  const { t, i18n } = useTranslation()
  const { file, folder, media } = photo
  const taken = formatTaken(photo, i18n.language)
  const place = media?.lat !== undefined && media.lon !== undefined ? { lat: media.lat, lon: media.lon } : null
  const coordinates = place ? `${place.lat.toFixed(5)}, ${place.lon.toFixed(5)}` : null
  // Maps are off for this person (or still loading): the place stays as coordinates below.
  const placeholder = (
    <div className="flex h-40 w-full flex-col items-center justify-center gap-1 bg-muted px-4 text-center text-sm text-muted-foreground">
      <MapPin className="size-5" aria-hidden />
      <a href={appUrl('account', '/settings/maps')} className="text-xs text-primary underline-offset-4 hover:underline">
        {t('info.mapsOff')}
      </a>
    </div>
  )

  return (
    <aside
      aria-label={t('viewer.info')}
      className="absolute inset-x-0 bottom-0 z-20 max-h-[60svh] overflow-y-auto rounded-t-xl bg-background text-foreground shadow-xl sm:static sm:max-h-none sm:w-80 sm:shrink-0 sm:rounded-none sm:border-l sm:border-border"
    >
      <div className="flex items-center justify-between px-4 pb-2 pt-3">
        <h2 className="font-display text-base font-semibold">{t('viewer.info')}</h2>
        <div className="flex items-center gap-1">
          {onEdit ? (
            <Button variant="outline" size="sm" onClick={onEdit}>
              <Pencil /> {t('info.edit')}
            </Button>
          ) : null}
          <Button variant="ghost" size="icon" aria-label={t('common.close')} onClick={onClose}>
            <X />
          </Button>
        </div>
      </div>
      <dl className="space-y-4 px-4 pb-6">
        {media?.caption ? <Row label={t('info.caption')}><span className="whitespace-pre-wrap">{media.caption}</span></Row> : null}
        <Row label={t('info.taken')}>
          {photo.dated ? (
            <>
              {taken.date}
              <span className="block text-muted-foreground">
                {taken.time}
                {taken.zone ? ` · ${taken.zone}` : ''}
              </span>
            </>
          ) : (
            <span className="text-muted-foreground">{t('info.dateUnknown')}</span>
          )}
        </Row>
        {place ? (
          <div className="space-y-2">
            <dt className="text-xs text-muted-foreground">{t('info.place')}</dt>
            <dd className="space-y-2">
              <div className="h-40 overflow-hidden rounded-lg border border-border">
                <Suspense fallback={placeholder}>
                  <MapView
                    center={place}
                    zoom={13}
                    markers={[place]}
                    interactive={false}
                    fallback={placeholder}
                    className="h-40 w-full"
                    ariaLabel={t('info.mapLabel')}
                  />
                </Suspense>
              </div>
              <p className="font-mono text-xs text-muted-foreground">{coordinates}</p>
              <p className="text-xs text-muted-foreground">{t('info.placeShared')}</p>
            </dd>
          </div>
        ) : null}
        {media?.camera ? <Row label={t('info.camera')}>{media.camera}</Row> : null}
        {media?.width && media.height ? (
          <Row label={t('info.dimensions')}>
            {t('info.pixels', { width: media.width, height: media.height, megapixels: ((media.width * media.height) / 1e6).toFixed(1) })}
          </Row>
        ) : null}
        {photo.kind === 'video' && media?.durationMs !== undefined ? <Row label={t('info.length')}>{formatDuration(media.durationMs)}</Row> : null}
        {photo.live ? (
          <Row label={t('info.live')}>
            {photo.live.file.name}
            {photo.live.media?.durationMs !== undefined ? <span className="block text-muted-foreground">{formatDuration(photo.live.media.durationMs)}</span> : null}
          </Row>
        ) : null}
        <Row label={t('info.file')}>
          {file.name}
          <span className="block text-muted-foreground">{formatBytes(file.size, i18n.language)}</span>
        </Row>
        {/* Someone else's photo, seen through an album, has no folder here. */}
        {folder.key ? (
          <Row label={t('info.folder')}>
            <a
              href={driveFolderUrl(folder)}
              className="inline-flex items-center gap-1 text-primary underline-offset-4 hover:underline"
            >
              {folder.isRoot ? t('info.myFiles') : (folder.name ?? '')}
              <ExternalLink className="size-3.5" aria-hidden />
            </a>
          </Row>
        ) : null}
      </dl>
    </aside>
  )
}
