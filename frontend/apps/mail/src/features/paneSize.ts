import { useCallback, useState } from 'react'

export type Layout = 'column' | 'row'

/** The list's width in the column layout and its height in the row layout, in pixels. */
export const DEFAULTS: Record<Layout, number> = { column: 416, row: 320 }
export const LIMITS: Record<Layout, [number, number]> = { column: [280, 720], row: [160, 640] }
const key = (layout: Layout) => `kutup.mail.listSize.${layout}`

function clamp(layout: Layout, size: number) {
  const [min, max] = LIMITS[layout]
  return Math.round(Math.min(max, Math.max(min, size)))
}

function stored(layout: Layout): number {
  try {
    const value = Number(localStorage.getItem(key(layout)))
    return value ? clamp(layout, value) : DEFAULTS[layout]
  } catch {
    return DEFAULTS[layout]
  }
}

/** The list pane's size, remembered in this browser (Proton keeps its resized list per device too). */
export function usePaneSize(layout: Layout) {
  const [sizes, setSizes] = useState<Record<Layout, number>>(() => ({ column: stored('column'), row: stored('row') }))
  const set = useCallback(
    (size: number) => {
      const next = clamp(layout, size)
      setSizes((now) => ({ ...now, [layout]: next }))
      try {
        localStorage.setItem(key(layout), String(next))
      } catch {
        // Not remembered: private windows and blocked storage.
      }
    },
    [layout],
  )
  return [sizes[layout], set] as const
}
