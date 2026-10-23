import { ShieldAlert } from 'lucide-react'
import type { PointerEvent as ReactPointerEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '@kutup/ui/lib/cn'
import { openEditor } from './editorState'
import { formatTime } from './format'
import type { Placed } from './placement'
import { useCalendarPrefs } from './prefs'

/**
 * An event in a day grid (the all-day row, the month): opens on a click or
 * Enter; `onPointerDown` lets the grid drag it by days.
 */
export function EventChip({
  placed,
  showTime,
  onPointerDown,
  faded = false,
}: {
  placed: Placed
  showTime: boolean
  onPointerDown?: (event: ReactPointerEvent) => void
  faded?: boolean
}) {
  const { t, i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  const title = placed.event.fields.summary ?? t('events.untitled')
  return (
    <button
      type="button"
      onPointerDown={onPointerDown}
      onClick={(e) => {
        e.stopPropagation()
        // A pointer's click is the grid's (a press that may have dragged); a key's is this button's.
        if (onPointerDown && e.detail > 0) return
        openEditor({ kind: 'edit', event: placed.event })
      }}
      className={cn('flex w-full min-w-0 touch-pan-y items-center gap-1 truncate rounded px-1.5 py-0.5 text-left text-xs hover:brightness-95', faded && 'opacity-40')}
      style={{ background: `${placed.color}26`, borderLeft: `3px solid ${placed.color}` }}
      data-testid="calendar-event"
    >
      {!placed.event.verified ? <ShieldAlert className="size-3 shrink-0 text-destructive" aria-label={t('events.unverifiedShort')} /> : null}
      {showTime && !placed.allDay ? <span className="shrink-0 tabular-nums text-muted-foreground">{formatTime(placed.start, i18n.language, prefs.hour12)}</span> : null}
      <span className="truncate">{title}</span>
    </button>
  )
}
