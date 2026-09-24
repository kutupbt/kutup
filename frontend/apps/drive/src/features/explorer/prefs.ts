import { useCallback, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { FILE_KINDS, type ItemKind } from './kinds'
import { DEFAULT_SORT, SORT_FIELDS, type SortDir, type SortField, type SortSpec } from './sort'

export type ViewMode = 'list' | 'grid'

export interface ExplorerPrefs {
  sort: SortSpec
  kinds: ReadonlySet<ItemKind>
  view: ViewMode
  /** Thumbnails in grid cards; off shows only kind icons. */
  showPreviews: boolean
}

const STORAGE_KEY = 'kutup-drive-view'
const ALL_KINDS: readonly ItemKind[] = ['folder', ...FILE_KINDS]

interface Stored {
  field?: SortField
  dir?: SortDir
  foldersFirst?: boolean
  view?: ViewMode
  showPreviews?: boolean
}

function readStored(): Stored {
  try {
    return (JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}') as Stored) ?? {}
  } catch {
    return {}
  }
}

function writeStored(value: Stored): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(value))
  } catch {
    // Storage unavailable: the choice still lives in the URL.
  }
}

function oneOf<T extends string>(value: string | null, options: readonly T[]): T | undefined {
  return options.find((o) => o === value)
}

/**
 * Sort, filter and view for the unified list. The current choice lives in the
 * URL (`?sort=name&dir=asc&kind=note,pdf&view=grid`) so back/forward and
 * shared links keep it; the last sort, "folders first" and view are also
 * remembered as this browser's default for every folder. The type filter is
 * per visit and never remembered — a hidden filter is how files "disappear".
 */
export function useExplorerPrefs(): [ExplorerPrefs, (patch: Partial<Stored> & { kinds?: ReadonlySet<ItemKind> }) => void] {
  const [params, setParams] = useSearchParams()
  const [stored, setStored] = useState<Stored>(readStored)

  const prefs = useMemo<ExplorerPrefs>(() => {
    const field = oneOf(params.get('sort'), SORT_FIELDS) ?? stored.field ?? DEFAULT_SORT.field
    const dir = oneOf(params.get('dir'), ['asc', 'desc'] as const) ?? stored.dir ?? DEFAULT_SORT.dir
    const view = oneOf(params.get('view'), ['list', 'grid'] as const) ?? stored.view ?? 'list'
    const kinds = new Set(
      (params.get('kind') ?? '').split(',').filter((k): k is ItemKind => ALL_KINDS.includes(k as ItemKind)),
    )
    return {
      sort: { field, dir, foldersFirst: stored.foldersFirst ?? DEFAULT_SORT.foldersFirst },
      kinds,
      view,
      showPreviews: stored.showPreviews ?? true,
    }
  }, [params, stored])

  const update = useCallback(
    (patch: Partial<Stored> & { kinds?: ReadonlySet<ItemKind> }) => {
      const { kinds, ...rest } = patch
      const next = { ...readStored(), ...rest }
      writeStored(next)
      setStored(next)
      setParams(
        (current) => {
          const out = new URLSearchParams(current)
          const set = (key: string, value: string | undefined, fallback: string) =>
            value === undefined || value === fallback ? out.delete(key) : out.set(key, value)
          if ('field' in rest) set('sort', rest.field, DEFAULT_SORT.field)
          if ('dir' in rest) set('dir', rest.dir, DEFAULT_SORT.dir)
          if ('view' in rest) set('view', rest.view, 'list')
          if (kinds) set('kind', [...kinds].join(','), '')
          return out
        },
        { replace: true },
      )
    },
    [setParams],
  )

  return [prefs, update]
}
