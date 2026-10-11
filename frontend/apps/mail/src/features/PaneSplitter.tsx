import { type KeyboardEvent, type PointerEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '@kutup/ui/lib/cn'
import { DEFAULTS, LIMITS, type Layout } from './paneSize'

/** The handle between the list and the reading pane: drag it, or use the arrow keys. */
export function PaneSplitter({ layout, size, onResize }: { layout: Layout; size: number; onResize: (size: number) => void }) {
  const { t } = useTranslation()
  const column = layout === 'column'
  function onPointerDown(e: PointerEvent<HTMLDivElement>) {
    e.preventDefault()
    const handle = e.currentTarget
    handle.setPointerCapture(e.pointerId)
    const start = column ? e.clientX : e.clientY
    const from = size
    const move = (event: globalThis.PointerEvent) => onResize(from + (column ? event.clientX : event.clientY) - start)
    const up = () => {
      handle.removeEventListener('pointermove', move)
      handle.removeEventListener('pointerup', up)
      handle.removeEventListener('pointercancel', up)
    }
    handle.addEventListener('pointermove', move)
    handle.addEventListener('pointerup', up)
    handle.addEventListener('pointercancel', up)
  }
  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    const grow = column ? 'ArrowRight' : 'ArrowDown'
    const shrink = column ? 'ArrowLeft' : 'ArrowUp'
    if (e.key !== grow && e.key !== shrink) return
    e.preventDefault()
    onResize(size + (e.key === grow ? 1 : -1) * (e.shiftKey ? 64 : 16))
  }
  const [min, max] = LIMITS[layout]
  return (
    <div
      role="separator"
      aria-orientation={column ? 'vertical' : 'horizontal'}
      aria-label={t('list.resize')}
      aria-valuenow={size}
      aria-valuemin={min}
      aria-valuemax={max}
      tabIndex={0}
      onPointerDown={onPointerDown}
      onKeyDown={onKeyDown}
      onDoubleClick={() => onResize(DEFAULTS[layout])}
      className={cn(
        'relative z-10 hidden shrink-0 touch-none bg-border transition-colors hover:bg-primary/50 focus-visible:bg-primary focus-visible:outline-none md:block',
        column ? 'w-px cursor-col-resize before:absolute before:inset-y-0 before:-left-1 before:-right-1' : 'h-px cursor-row-resize before:absolute before:inset-x-0 before:-top-1 before:-bottom-1',
      )}
    />
  )
}
