import { useCallback, useEffect, useRef, useState, type PointerEvent as ReactPointerEvent, type RefObject } from 'react'

export interface MarqueeRect {
  left: number
  top: number
  width: number
  height: number
}

/** Pixels the pointer must travel before a press on empty space becomes a box. */
const THRESHOLD = 4
/** Distance from the window edge where dragging scrolls the page. */
const EDGE = 48

/** Whether two rectangles (surface coordinates) overlap. */
export function intersects(a: MarqueeRect, b: MarqueeRect): boolean {
  return a.left < b.left + b.width && b.left < a.left + a.width && a.top < b.top + b.height && b.top < a.top + a.height
}

export function rectBetween(ax: number, ay: number, bx: number, by: number): MarqueeRect {
  return { left: Math.min(ax, bx), top: Math.min(ay, by), width: Math.abs(ax - bx), height: Math.abs(ay - by) }
}

/**
 * Rubber-band selection, the way desktop file managers do it: press on empty
 * space and drag to select every item the box touches. Ctrl/⌘ or Shift adds
 * to the selection that was there; a plain press on empty space clears it.
 *
 * Coordinates are kept relative to the surface, so the box stays anchored
 * while the page scrolls under it (dragging near the window's top or bottom
 * edge scrolls). Mouse and pen only: on touch, a drag scrolls.
 */
export function useMarquee({
  surface,
  items,
  selection,
  onSelect,
  onClear,
}: {
  surface: RefObject<HTMLElement | null>
  /** The item elements, in display order, and their keys. */
  items: () => { key: string; el: HTMLElement | null }[]
  /** The selection now; an additive box adds to what it was when the drag began. */
  selection: () => ReadonlySet<string>
  onSelect: (keys: Set<string>) => void
  onClear: () => void
}) {
  const [rect, setRect] = useState<MarqueeRect | null>(null)
  const drag = useRef<{
    x: number
    y: number
    additive: boolean
    base: ReadonlySet<string>
    active: boolean
    lastClientX: number
    lastClientY: number
  } | null>(null)
  const callbacks = useRef({ items, selection, onSelect, onClear })
  callbacks.current = { items, selection, onSelect, onClear }

  const update = useCallback(
    (clientX: number, clientY: number) => {
      const d = drag.current
      const el = surface.current
      if (!d || !el) return
      d.lastClientX = clientX
      d.lastClientY = clientY
      const origin = el.getBoundingClientRect()
      const x = clientX - origin.left
      const y = clientY - origin.top
      if (!d.active && Math.hypot(x - d.x, y - d.y) < THRESHOLD) return
      d.active = true
      const box = rectBetween(d.x, d.y, x, y)
      setRect(box)
      const hit = new Set<string>(d.base)
      for (const { key, el: item } of callbacks.current.items()) {
        if (!item) continue
        const r = item.getBoundingClientRect()
        const itemBox = { left: r.left - origin.left, top: r.top - origin.top, width: r.width, height: r.height }
        if (intersects(box, itemBox)) hit.add(key)
      }
      callbacks.current.onSelect(hit)
    },
    [surface],
  )

  useEffect(() => {
    if (!rect) return
    // While a box is open, scrolling (the wheel, or the edge scroll below)
    // moves the items under it: re-test against where the pointer is now.
    const onScroll = () => {
      const d = drag.current
      if (d) update(d.lastClientX, d.lastClientY)
    }
    window.addEventListener('scroll', onScroll, true)
    return () => window.removeEventListener('scroll', onScroll, true)
  }, [rect, update])

  const onPointerDown = useCallback(
    (event: ReactPointerEvent) => {
      if (event.button !== 0 || event.pointerType === 'touch') return
      const target = event.target as HTMLElement
      // Presses on an item, a control or a header belong to them.
      if (target.closest('[data-item-key], button, a, input, th, [role="menu"]')) return
      const el = surface.current
      if (!el) return
      const origin = el.getBoundingClientRect()
      const additive = event.ctrlKey || event.metaKey || event.shiftKey
      drag.current = {
        x: event.clientX - origin.left,
        y: event.clientY - origin.top,
        additive,
        base: additive ? new Set(callbacks.current.selection()) : new Set(),
        active: false,
        lastClientX: event.clientX,
        lastClientY: event.clientY,
      }
      // No text selection while dragging a box.
      event.preventDefault()

      const onMove = (e: PointerEvent) => {
        update(e.clientX, e.clientY)
        if (e.clientY > window.innerHeight - EDGE) window.scrollBy(0, 16)
        else if (e.clientY < EDGE) window.scrollBy(0, -16)
      }
      const onUp = () => {
        window.removeEventListener('pointermove', onMove)
        window.removeEventListener('pointerup', onUp)
        window.removeEventListener('pointercancel', onUp)
        const d = drag.current
        drag.current = null
        setRect(null)
        // A click on empty space, not a drag: deselect, like a desktop.
        if (d && !d.active && !d.additive) callbacks.current.onClear()
      }
      window.addEventListener('pointermove', onMove)
      window.addEventListener('pointerup', onUp)
      window.addEventListener('pointercancel', onUp)
    },
    [surface, update],
  )

  return { rect, onPointerDown }
}
