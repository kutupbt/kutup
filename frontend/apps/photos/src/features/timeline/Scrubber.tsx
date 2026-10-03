import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { formatMonth } from '../library/format'

interface Props {
  /** Each month heading, newest first, and its row. */
  months: { month: string; index: number }[]
  onJump: (index: number) => void
}

/**
 * Jump through the years (Proton's fast scroller): pressing or dragging along
 * the track goes to the month under the pointer, its name shown beside it.
 * The years are buttons for the keyboard.
 */
export function Scrubber({ months, onJump }: Props) {
  const { t, i18n } = useTranslation()
  const track = useRef<HTMLDivElement>(null)
  const [hover, setHover] = useState<{ at: number; month: string } | null>(null)
  const dragging = useRef(false)

  const pick = (clientY: number) => {
    const el = track.current
    if (!el) return null
    const box = el.getBoundingClientRect()
    const ratio = Math.min(1, Math.max(0, (clientY - box.top) / box.height))
    const entry = months[Math.min(months.length - 1, Math.floor(ratio * months.length))]
    return { entry, at: ratio * box.height }
  }

  const years: { year: string; slot: number; index: number }[] = []
  months.forEach((m, slot) => {
    const year = m.month.slice(0, 4)
    if (years[years.length - 1]?.year !== year) years.push({ year, slot, index: m.index })
  })

  return (
    <div className="sticky top-14 hidden h-[calc(100svh-3.5rem)] w-12 shrink-0 select-none py-4 md:block">
      <div
        ref={track}
        className="relative h-full cursor-ns-resize touch-none"
        aria-label={t('timeline.jump')}
        role="group"
        onPointerDown={(e) => {
          dragging.current = true
          e.currentTarget.setPointerCapture(e.pointerId)
          const hit = pick(e.clientY)
          if (hit) onJump(hit.entry.index)
        }}
        onPointerMove={(e) => {
          const hit = pick(e.clientY)
          setHover(hit ? { at: hit.at, month: hit.entry.month } : null)
          if (hit && dragging.current) onJump(hit.entry.index)
        }}
        onPointerUp={() => {
          dragging.current = false
        }}
        onPointerLeave={() => {
          if (!dragging.current) setHover(null)
        }}
      >
        {years.map((y) => (
          <button
            key={y.year}
            type="button"
            onClick={() => onJump(y.index)}
            className="absolute right-1 -translate-y-1/2 rounded px-1 text-[11px] font-medium tabular-nums text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            style={{ top: `${((y.slot + 0.5) / months.length) * 100}%` }}
          >
            {y.year}
          </button>
        ))}
        {hover ? (
          <>
            <span className="pointer-events-none absolute inset-x-1 h-0.5 rounded bg-primary" style={{ top: hover.at }} />
            <span
              className="pointer-events-none absolute right-12 -translate-y-1/2 whitespace-nowrap rounded-md bg-foreground px-2 py-1 text-xs font-medium text-background shadow"
              style={{ top: hover.at }}
            >
              {formatMonth(hover.month, i18n.language)}
            </span>
          </>
        ) : null}
      </div>
    </div>
  )
}
