import type { ItemKind } from './kinds'

/** One row of the unified list: a folder or a file, side by side. */
export interface ExplorerItem {
  type: 'folder' | 'file'
  id: string
  name: string
  kind: ItemKind
  /** Plaintext size; null for folders. */
  size: number | null
  /** RFC 3339; the list's default sort. */
  modifiedAt: string
  /** A folder's chosen colour (hex), if any. */
  color?: string | null
}

/** Stable selection key: folders and files share one list, and their ids do not. */
export function itemKey(item: Pick<ExplorerItem, 'type' | 'id'>): string {
  return `${item.type}:${item.id}`
}

export const SORT_FIELDS = ['modified', 'name', 'size', 'type'] as const
export type SortField = (typeof SORT_FIELDS)[number]
export type SortDir = 'asc' | 'desc'

export interface SortSpec {
  field: SortField
  dir: SortDir
  /** Dolphin's option; Google Drive's default (off) mixes them. */
  foldersFirst: boolean
}

export const DEFAULT_SORT: SortSpec = { field: 'modified', dir: 'desc', foldersFirst: false }

function collator(locale: string): Intl.Collator {
  return new Intl.Collator(locale, { numeric: true, sensitivity: 'base' })
}

/**
 * Sort the unified list. Names compare naturally ("file 2" before
 * "file 10") in the user's locale; every comparison ties on name so the order
 * is stable. Folders have no size: sorted by size they sit at the small end.
 * Sorting by type groups folders together (their kind is "folder").
 */
export function sortItems(items: readonly ExplorerItem[], spec: SortSpec, locale: string): ExplorerItem[] {
  const names = collator(locale)
  const sign = spec.dir === 'asc' ? 1 : -1
  const byName = (a: ExplorerItem, b: ExplorerItem) => names.compare(a.name, b.name)
  const primary = (a: ExplorerItem, b: ExplorerItem): number => {
    switch (spec.field) {
      case 'name':
        return byName(a, b)
      case 'modified':
        return Date.parse(a.modifiedAt) - Date.parse(b.modifiedAt)
      case 'size':
        return (a.size ?? -1) - (b.size ?? -1)
      case 'type':
        return names.compare(a.kind, b.kind)
    }
  }
  return [...items].sort((a, b) => {
    if (spec.foldersFirst && a.type !== b.type) return a.type === 'folder' ? -1 : 1
    return sign * primary(a, b) || byName(a, b)
  })
}

/** Keep items whose kind is selected; an empty selection keeps everything. */
export function filterItems(items: readonly ExplorerItem[], kinds: ReadonlySet<ItemKind>): ExplorerItem[] {
  return kinds.size === 0 ? [...items] : items.filter((item) => kinds.has(item.kind))
}
