import { isAxiosError } from 'axios'
import { wrapFileKeyForV1 } from '@kutup/crypto/fileRecord'
import api from '@kutup/session/client'
import type { DriveFile, Folder } from './model'
import { asNameTaken, contentHashIn, inFolder, nameHashIn } from './names'
import { rekeyFile } from './rekey'

// Moving a file (docs/plans/drive-move.md). Everything sealed under a file's
// key is bound to the file alone; only the wrap of that key names its
// folder, so a move re-seals one small envelope for the destination and
// nothing else. Drive moves files and folders; Pass moves vaults (files),
// which keep their id, so a vault's kept key still opens it.

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
  if (!file.fileKey || !file.name) throw new Error('file is not open')
  const fileKeyEnvelope = await wrapFileKeyForV1(file, file.fileKey, to.id, to.keyEpoch, to.key)
  try {
    // The name's hash belongs to the folder: the destination's. Its content
    // hash does too: worked out again from the SHA-256 in its metadata, as
    // Proton's move recomputes ContentHash — but only while the one it has
    // stands (an editor's save clears it, and leaves the SHA-256 behind)
    // (docs/plans/drive-unique-names.md).
    await api.post(`/files/${file.id}/move`, {
      fromCollectionId: from.id,
      toCollectionId: to.id,
      toKeyEpoch: to.keyEpoch,
      fileKeyEnvelope,
      nameHash: await nameHashIn(inFolder(to), file.name),
      ...(file.contentHash && file.sha256 ? { contentHash: await contentHashIn(to, file.sha256) } : {}),
    })
  } catch (error) {
    if (asNameTaken(error)) throw new MoveNameTakenError()
    const reason = conflictReason(error)
    if (reason) throw new MoveConflictError(reason)
    throw error
  }
}

