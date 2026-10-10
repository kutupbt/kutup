import { useWindowVirtualizer } from '@tanstack/react-virtual'
import { useEffect, useLayoutEffect, useRef, useState, type MutableRefObject, type RefObject } from 'react'

/** The items drawn (`from` up to `to`), and the space the others take above and below. */
export interface ShownRange {
  from: number
  to: number
  before: number
  after: number
}

/**
 * Which items a long listing draws (Drive's Explorer, the Office home): only the rows near the screen, the rest
 * stood in for by empty space (docs/research/18-web-performance.md: every
 * row drawn costs about half a millisecond, two on a slow phone). Always,
 * whatever the count, as Proton Drive's lists do: one code path, and a
 * folder never changes behaviour as it grows. Proton's settings
 * (kutup-references/WebClients, applications/drive/src/app/
 * statelessComponents/DriveExplorer: useListVirtualizer.ts,
 * useGridVirtualizer.ts, constants.ts): TanStack Virtual, 5 rows drawn
 * beyond the screen above and below, in the list and the grid alike. Rows are as tall as the
 * first one drawn and, in the grid, as wide as the tiles that fit; both are
 * measured from what is on screen. `focus` scrolls an item that is not drawn
 * into view first.
 */
export function useShownRange(
  count: number,
  grid: boolean,
  surface: RefObject<HTMLElement | null>,
  rowRefs: MutableRefObject<(HTMLElement | null)[]>,
): { range: ShownRange; focus: (index: number) => void } {
  const virtual = count > 0
  const [columns, setColumns] = useState(1)
  const [rowHeight, setRowHeight] = useState(grid ? 260 : 49)
  const [margin, setMargin] = useState(0)
  const perRow = grid ? columns : 1
  const rows = Math.ceil(count / perRow)
  const virtualizer = useWindowVirtualizer({
    count: virtual ? rows : 0,
    estimateSize: () => rowHeight,
    // Proton's `defaultConfig.overscan`.
    overscan: 5,
    scrollMargin: margin,
  })
  useEffect(() => {
    virtualizer.measure()
  }, [virtualizer, rowHeight, perRow])

  const virtualRows = virtual ? virtualizer.getVirtualItems() : []
  const range: ShownRange =
    virtual && virtualRows.length > 0
      ? {
          from: virtualRows[0].index * perRow,
          to: Math.min(count, (virtualRows[virtualRows.length - 1].index + 1) * perRow),
          before: virtualRows[0].start - margin,
          after: Math.max(0, virtualizer.getTotalSize() - (virtualRows[virtualRows.length - 1].end - margin)),
        }
      : { from: 0, to: virtual ? Math.min(count, 60) : count, before: 0, after: 0 }

  // Where the listing starts on the page, how tall a row is and, in the
  // grid, how many tiles a row holds: read from what is drawn, after every
  // render (a banner above, a resized window and a new view all move them);
  // each is set only when it changed, so this settles at once.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useLayoutEffect(() => {
    if (!virtual) return
    const el = surface.current
    if (el) {
      const top = Math.round(el.getBoundingClientRect().top + window.scrollY)
      if (top !== margin) setMargin(top)
    }
    const first = rowRefs.current[range.from]
    if (!first) return
    if (grid) {
      let across = 0
      for (let i = range.from; i < range.to && rowRefs.current[i]?.offsetTop === first.offsetTop; i++) across++
      const next = range.from + across < range.to ? rowRefs.current[range.from + across] : null
      const height = next ? next.offsetTop - first.offsetTop : first.offsetHeight
      if (across > 0 && across !== columns) setColumns(across)
      if (height > 0 && height !== rowHeight) setRowHeight(height)
    } else if (first.offsetHeight > 0 && first.offsetHeight !== rowHeight) {
      setRowHeight(first.offsetHeight)
    }
  })

  const pendingFocus = useRef<number | null>(null)
  useEffect(() => {
    const index = pendingFocus.current
    if (index === null) return
    const el = rowRefs.current[index]
    if (el) {
      pendingFocus.current = null
      el.focus()
    }
  })
  const focus = (index: number) => {
    const el = rowRefs.current[index]
    if (el) {
      el.focus()
      return
    }
    if (!virtual) return
    pendingFocus.current = index
    virtualizer.scrollToIndex(Math.floor(index / perRow), { align: 'auto' })
  }
  return { range, focus }
}
