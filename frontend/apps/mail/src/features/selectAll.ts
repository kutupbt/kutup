import type { FolderId } from '@kutup/mail-core/api'
import type { Destination } from './mailActions'

/** What select all does to every message of a place. */
export type AllAction = { kind: 'mark'; seen: boolean } | { kind: 'move'; destination: Destination } | { kind: 'label'; add: string[]; remove: string[] }

/**
 * Proton's rule for the banner (`getCanDisplaySelectAllBanner`): a whole
 * page checked, outside All mail, with no search and no filter.
 */
export function canSelectAll({ checked, pageSize, folder, own, q, filtered }: { checked: number; pageSize: number; folder: FolderId; own: boolean; q: string; filtered: boolean }): boolean {
  return checked === pageSize && (own || folder !== 'all') && !q && !filtered
}
