import { Check, ImageOff, Play } from 'lucide-react'
import { memo, useEffect, useState } from 'react'
import { useThumbnail } from './useThumbnail'
import { useTranslation } from 'react-i18next'
import { cn } from '@kutup/ui/lib/cn'
import { catchUp } from '../library/catchUp'
import { formatDuration, formatTaken } from '../library/format'
import type { Photo } from '../library/library'

interface TileProps {
  photo: Photo
  userId: string
  size: number
  selected: boolean
  /** Something is selected: a click selects rather than opens. */
  selecting: boolean
  onOpen: (photo: Photo) => void
  onToggle: (photo: Photo, range: boolean) => void
}

/**
 * One square of the grid: the photo's thumbnail filling it, a video's length,
 * and a check to select it. On screen and missing its details or picture, it
 * moves to the front of the background catch-up.
 */
export const PhotoTile = memo(function PhotoTile({ photo, userId, size, selected, selecting, onOpen, onToggle }: TileProps) {
  const { t, i18n } = useTranslation()
  const url = useThumbnail(photo)
  const [broken, setBroken] = useState(false)
  const needs = !photo.media || !photo.file.thumbnails.sm

  useEffect(() => {
    if (needs) catchUp(photo, userId, true)
    // Once per photo on screen.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [photo.id, needs])

  const taken = formatTaken(photo, i18n.language)
  const label = `${photo.file.name ?? ''}, ${taken.date} ${taken.time}`
  return (
    <div className="group relative overflow-hidden bg-muted" style={{ width: size, height: size }}>
      <button
        type="button"
        className="absolute inset-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
        aria-label={label}
        onClick={(e) => (selecting || e.shiftKey ? onToggle(photo, e.shiftKey) : onOpen(photo))}
      >
        {url && !broken ? (
          <img
            src={url}
            alt=""
            draggable={false}
            onError={() => setBroken(true)}
            className={cn('size-full object-cover transition-transform', selected && 'scale-[0.88] rounded-md')}
          />
        ) : (
          <span className="flex size-full items-center justify-center text-muted-foreground">
            {photo.file.thumbnails.sm && !broken ? null : <ImageOff className="size-6 opacity-40" aria-hidden />}
          </span>
        )}
      </button>
      {photo.kind === 'video' ? (
        <span className="pointer-events-none absolute bottom-1.5 right-1.5 flex items-center gap-1 rounded bg-black/60 px-1.5 py-0.5 text-[11px] font-medium tabular-nums text-white">
          <Play className="size-3 fill-current" aria-hidden />
          {photo.media?.durationMs !== undefined ? formatDuration(photo.media.durationMs) : null}
        </span>
      ) : null}
      <button
        type="button"
        role="checkbox"
        aria-checked={selected}
        aria-label={t('timeline.select', { name: photo.file.name ?? '' })}
        onClick={(e) => onToggle(photo, e.shiftKey)}
        className={cn(
          'absolute left-1.5 top-1.5 flex size-6 items-center justify-center rounded-full border-2 transition-opacity focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
          selected
            ? 'border-primary bg-primary text-primary-foreground opacity-100'
            : 'border-white/90 bg-black/20 text-transparent opacity-0 group-hover:opacity-100',
          selecting && 'opacity-100',
        )}
      >
        <Check className="size-3.5" strokeWidth={3} aria-hidden />
      </button>
    </div>
  )
})
