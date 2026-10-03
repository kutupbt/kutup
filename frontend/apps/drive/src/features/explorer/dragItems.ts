import type { DragEvent } from 'react'

/**
 * Items dragged inside the app (to move them), as opposed to files dragged
 * in from the desktop (to upload them). A drop target cannot read the
 * payload while the drag is still over it, so the keys are kept here too.
 */
export const ITEM_DRAG_TYPE = 'application/x-kutup-items'

let dragged: string[] | null = null

export function startItemDrag(keys: string[], event: DragEvent): void {
  dragged = keys
  event.dataTransfer.effectAllowed = 'move'
  event.dataTransfer.setData(ITEM_DRAG_TYPE, keys.join('\n'))
}

/** The keys being dragged, or null when nothing from the app is. */
export function draggedItems(): string[] | null {
  return dragged
}

export function endItemDrag(): void {
  dragged = null
}
