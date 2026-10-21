import api from '@kutup/session/client'
import { getSession } from '@kutup/session/store'
import { atTopLevel, asNameTaken, canonicalName, inFolder, nameHashIn } from '@kutup/drive-core/names'
import { isWithin, namesIn } from './copy'
import { MoveNameTakenError } from '@kutup/drive-core/move'

// A file's move is shared with Pass (its vaults are files): drive-core.
export { MoveConflictError, MoveNameTakenError, moveFile } from '@kutup/drive-core/move'
import type { FolderIndex } from '@kutup/drive-core/folders'
import type { DriveFile, Folder } from '@kutup/drive-core/model'

// Moving (docs/plans/drive-move.md). Everything sealed under a file's key is
// bound to the file alone; only the wrap of that key names its folder, so a
// move re-seals one small envelope for the destination and nothing else. A
// folder's key is sealed to its owner, not its parent: moving one changes
// nothing encrypted. Across owners or servers it is a copy instead.

export type MoveSource = { folder: Folder; file?: undefined } | { folder: Folder; file: DriveFile }

/** Why an item cannot go into a folder. */
export type MoveRefusal =
  | 'locked'
  | 'readOnly'
  | 'otherOwner'
  | 'remote'
  | 'notOwner'
  | 'intoItself'
  | 'alreadyThere'

/** Why `source` cannot be moved into `dest`, or null when it can. */
export function moveRefusal(index: FolderIndex, source: MoveSource, dest: Folder): MoveRefusal | null {
  const from = source.folder
  if (!dest.key) return 'locked'
  if (dest.source === 'remote' || from.source === 'remote') return 'remote'
  if (source.file) {
    if (dest.id === from.id) return 'alreadyThere'
    if (!from.canUpload || !dest.canUpload) return 'readOnly'
    if (dest.ownerUserId !== from.ownerUserId) return 'otherOwner'
    return null
  }
  // A folder: only its owner moves it, and only among their own folders.
  if (!from.canManage || from.source !== 'owned') return 'notOwner'
  if (dest.source !== 'owned' || dest.ownerUserId !== from.ownerUserId) return 'otherOwner'
  if (isWithin(index, dest, from)) return 'intoItself'
  if (from.parentId === dest.id) return 'alreadyThere'
  return null
}

/** Put a folder under `parent`, or at the top level (null). Owner only. */
export async function moveFolder(folder: Folder, parent: Folder | null): Promise<void> {
  const masterKey = getSession()?.masterKey
  const place = parent ? inFolder(parent) : masterKey ? atTopLevel(masterKey) : null
  if (!place || !folder.name) throw new Error('folder is not open')
  try {
    await api.post(`/collections/${folder.id}/move`, {
      parentCollectionId: parent?.id ?? null,
      nameHash: await nameHashIn(place, folder.name),
    })
  } catch (error) {
    if (asNameTaken(error)) throw new MoveNameTakenError()
    throw error
  }
}

/** The names in `dest` that `sources` would clash with (case and composition aside, as the server compares). */
export async function clashes(index: FolderIndex, sources: MoveSource[], dest: Folder): Promise<Set<MoveSource>> {
  const taken = new Set((await namesIn(index, dest)).map(canonicalName))
  return new Set(
    sources.filter((s) => {
      const name = s.file ? s.file.name : s.folder.name
      return name !== null && taken.has(canonicalName(name))
    }),
  )
}
