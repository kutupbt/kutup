import { isAxiosError } from 'axios'
import { wrapFileKeyForV1 } from '@kutup/crypto/fileRecord'
import api from '@kutup/session/client'
import { getSession } from '@kutup/session/store'
import { atTopLevel, asNameTaken, canonicalName, inFolder, nameHashIn } from '@kutup/drive-core/names'
import { isWithin, namesIn } from './copy'
import type { FolderIndex } from '@kutup/drive-core/folders'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { rekeyFile } from '@kutup/drive-core/rekey'

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

/** A move the server refused because something changed meanwhile. */
export class MoveConflictError extends Error {
  constructor(readonly reason: string) {
    super(reason)
  }
}

/** A move the server refused because the name is taken in the destination. */
export class MoveNameTakenError extends Error {
  constructor() {
    super('an item with this name is already there')
  }
}

function conflictReason(error: unknown): string | null {
  if (!isAxiosError(error) || error.response?.status !== 409 || asNameTaken(error)) return null
  const data = error.response.data as { error?: string; message?: string } | string | undefined
  return typeof data === 'string' ? data : (data?.error ?? data?.message ?? 'conflict')
}

/**
 * Move a file from `from` to `to`: re-key it first if its folder has rotated
 * past it (so nobody removed from `from` can follow it), then wrap its key
 * for `to`. Returns nothing; the lists refetch.
 */
export async function moveFile(from: Folder, listed: DriveFile, to: Folder): Promise<void> {
  if (!to.key) throw new Error('destination is not open')
  const file = await rekeyFile(from, listed)
  if (!file.fileKey) throw new Error('file is not open')
  const fileKeyEnvelope = await wrapFileKeyForV1(file, file.fileKey, to.id, to.keyEpoch, to.key)
  try {
    // The name's hash belongs to the folder: the destination's. Its content
    // hash does too, and the plaintext's digest is not kept, so it is
    // dropped (docs/plans/drive-unique-names.md).
    await api.post(`/files/${file.id}/move`, {
      fromCollectionId: from.id,
      toCollectionId: to.id,
      toKeyEpoch: to.keyEpoch,
      fileKeyEnvelope,
      ...(file.name ? { nameHash: await nameHashIn(inFolder(to), file.name) } : {}),
    })
  } catch (error) {
    if (asNameTaken(error)) throw new MoveNameTakenError()
    const reason = conflictReason(error)
    if (reason) throw new MoveConflictError(reason)
    throw error
  }
}

/** Put a folder under `parent`, or at the top level (null). Owner only. */
export async function moveFolder(folder: Folder, parent: Folder | null): Promise<void> {
  const masterKey = getSession()?.masterKey
  const place = parent ? inFolder(parent) : masterKey ? atTopLevel(masterKey) : null
  try {
    await api.post(`/collections/${folder.id}/move`, {
      parentCollectionId: parent?.id ?? null,
      ...(folder.name && place ? { nameHash: await nameHashIn(place, folder.name) } : {}),
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
