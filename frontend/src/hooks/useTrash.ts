import { useMemo } from 'react'

/**
 * Trash data hook — single source of truth for the Trash UI (desktop table +
 * mobile list).
 *
 * Backend support for soft-delete + 30-day retention isn't wired yet (see
 * roadmap PRs 6/7 in /Users/aa/.claude/plans/so-after-some-changes-playful-wall.md).
 * Until that lands this hook returns an empty trash list so the Trash UI shows
 * its empty-state pattern in both layouts.
 *
 * Shape is intentionally close to the existing Drive entity model so wiring
 * later is a drop-in:
 *   - folders carry `name`, `color`, `items` count, `deletedAt`
 *   - files carry `name`, `size`, `mime`, `deletedAt`
 */

export interface TrashedFolder {
  id: string
  kind: 'folder'
  name: string
  color: string | null
  items: number
  deletedAt: string
}

export interface TrashedFile {
  id: string
  kind: 'file'
  name: string
  size: number
  mime: string
  deletedAt: string
}

export type TrashItem = TrashedFolder | TrashedFile

export interface UseTrashResult {
  items: TrashItem[]
  count: number
  isLoading: boolean
  restore: (id: string) => Promise<void>
  destroy: (id: string) => Promise<void>
  emptyAll: () => Promise<void>
}

const NOT_WIRED = async () => {
  // Backend trash endpoints don't exist yet — see roadmap PR 6.
  // The UI calls these handlers but they no-op until the API lands.
}

export function useTrash(): UseTrashResult {
  return useMemo<UseTrashResult>(
    () => ({
      items: [],
      count: 0,
      isLoading: false,
      restore: NOT_WIRED,
      destroy: NOT_WIRED,
      emptyAll: NOT_WIRED,
    }),
    [],
  )
}
