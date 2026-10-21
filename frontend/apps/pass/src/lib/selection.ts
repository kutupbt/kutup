// Several entries selected at once in a vault's entry list (docs/plans/pass-parity.md,
// "Bulk actions and the entry list"), as KeePassXC's and Mail's lists do: a
// checkbox or Ctrl/Cmd-click toggles one, Shift-click takes the range from the
// last one clicked, Ctrl+A takes everything shown.

export interface Selection {
  ids: ReadonlySet<string>
  /** The entry a Shift-click's range starts from. */
  anchor: string | null
}

export const emptySelection: Selection = { ids: new Set(), anchor: null }

/** Toggles `id`, which becomes the anchor. */
export function toggle(selection: Selection, id: string): Selection {
  const ids = new Set(selection.ids)
  if (ids.has(id)) ids.delete(id)
  else ids.add(id)
  return { ids, anchor: id }
}

/**
 * Adds the entries from the anchor to `id`, in the list's `order`, to what is
 * selected (or only `id` without an anchor still shown). The anchor stays.
 */
export function selectRange(selection: Selection, order: readonly string[], id: string): Selection {
  const to = order.indexOf(id)
  const from = selection.anchor === null ? -1 : order.indexOf(selection.anchor)
  if (to < 0) return selection
  if (from < 0) return toggle(selection, id)
  const ids = new Set(selection.ids)
  for (let i = Math.min(from, to); i <= Math.max(from, to); i++) ids.add(order[i])
  return { ids, anchor: selection.anchor }
}

/** Everything in `order`. */
export function selectAll(order: readonly string[]): Selection {
  return { ids: new Set(order), anchor: order[0] ?? null }
}

/**
 * What stays selected of what the list shows now: entries gone (deleted,
 * moved out by another device's save) drop out, and so does the anchor.
 */
export function keepShown(selection: Selection, order: readonly string[]): Selection {
  const shown = new Set(order)
  const ids = [...selection.ids].filter((id) => shown.has(id))
  const anchor = selection.anchor !== null && shown.has(selection.anchor) ? selection.anchor : null
  if (ids.length === selection.ids.size && anchor === selection.anchor) return selection
  return { ids: new Set(ids), anchor }
}

/** The selected ids in the list's order. */
export function inOrder(selection: Selection, order: readonly string[]): string[] {
  return order.filter((id) => selection.ids.has(id))
}
