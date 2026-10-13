/**
 * Whether the scene holds a change made here: an element newer than this
 * tab last sent or received (`seen`, element id → version). Others' edits
 * are recorded in `seen` as they are merged, so they never count.
 */
export function hasLocalChanges(elements: readonly { id: string; version?: number }[], seen: ReadonlyMap<string, number>): boolean {
  return elements.some((el) => (el.version ?? 0) > (seen.get(el.id) ?? -1))
}
