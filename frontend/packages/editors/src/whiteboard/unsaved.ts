/**
 * Whether the scene holds a change made here: an element newer than this
 * tab last sent or received (`seen`, element id → version). Others' edits
 * are recorded in `seen` as they are merged, so they never count.
 */
export function hasLocalChanges(elements: readonly { id: string; version?: number }[], seen: ReadonlyMap<string, number>): boolean {
  return elements.some((el) => (el.version ?? 0) > (seen.get(el.id) ?? -1))
}

/**
 * Whether a whiteboard holds drawing not yet stored: drawn since the last
 * stored save, or in a save that is still on its way. A save that fails
 * leaves its drawing unsaved.
 */
export class SaveTracker {
  private changed = false
  private pending = 0

  /** Something was drawn here. */
  markChanged(): void {
    this.changed = true
  }

  get hasChanges(): boolean {
    return this.changed
  }

  /** The scene was serialised for a save; call the result with whether it was stored. */
  beginSave(): (stored: boolean) => void {
    // Drawing after this point is new; what was serialised is pending.
    this.changed = false
    this.pending += 1
    let settled = false
    return (stored: boolean) => {
      if (settled) return
      settled = true
      this.pending -= 1
      if (!stored) this.changed = true
    }
  }

  get unsaved(): boolean {
    return this.changed || this.pending > 0
  }
}
