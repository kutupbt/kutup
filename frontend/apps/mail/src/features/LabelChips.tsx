import { X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { MailPlaces } from '@kutup/mail-core/places'
import { cn } from '@kutup/ui/lib/cn'

/** A message's labels as coloured chips (Proton's list and header); the first few, then "+n". */
export function LabelChips({
  ids,
  places,
  max = 3,
  onRemove,
  className,
}: {
  ids: string[]
  places: MailPlaces | undefined
  max?: number
  /** Shown as × on each chip (the reading pane). */
  onRemove?: (id: string) => void
  className?: string
}) {
  const { t } = useTranslation()
  const labels = ids.flatMap((id) => {
    const label = places?.labelsById.get(id)
    return label ? [label] : []
  })
  if (labels.length === 0) return null
  const shown = onRemove ? labels : labels.slice(0, max)
  return (
    <span className={cn('flex min-w-0 shrink items-center gap-1', className)}>
      {shown.map((label) => (
        <span
          key={label.id}
          className="inline-flex max-w-[9rem] items-center gap-1 rounded-full border px-1.5 text-[11px] leading-5"
          style={{ borderColor: label.color, color: label.color }}
        >
          <span className="truncate">{label.name}</span>
          {onRemove ? (
            <button
              type="button"
              className="-mr-0.5 rounded-full hover:bg-muted"
              aria-label={t('places.removeLabel', { name: label.name })}
              onClick={(e) => {
                e.stopPropagation()
                onRemove(label.id)
              }}
            >
              <X className="size-3" />
            </button>
          ) : null}
        </span>
      ))}
      {labels.length > shown.length ? <span className="text-[11px] text-muted-foreground">+{labels.length - shown.length}</span> : null}
    </span>
  )
}
