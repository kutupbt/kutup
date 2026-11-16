// Saves that commit a file's next metadata in the same request (a whole-file
// version, a note's saved state; docs/plans/drive-block-format.md §2): the
// next revision is sealed on top of the file's metadata as last known, and
// when someone else's landed first (`409 revision_conflict`), on top of
// theirs, once.

import { openFileMetadataV1, renameFileRecordV1, type FileMetadataV2 } from '@kutup/crypto'
import { MetadataConflictError, type CurrentMetadata } from '@kutup/session/errors'
import { acceptFileMetadata } from './metadataGuard'
import { fileMetadataOf, type DriveFile } from './model'

/** A file as a save commits its next metadata on top of it. Each commit moves `file` on. */
export interface MetadataTarget {
  /** The file's current key, and the file and generation it seals for. */
  fileKey: Uint8Array
  context: { fileId: string; generation: number }
  /**
   * The file as last known: its folder (to read it again), its metadata
   * revision and metadata (null when it did not open).
   */
  file: { collectionId: string; metadataRevision: number; metadata: FileMetadataV2 | null }
  /**
   * Reads the file's metadata again, for a conflict that doesn't carry it.
   * Without it, a conflict that carries none is thrown as it came.
   */
  reread?: () => Promise<CurrentMetadata & { keyGeneration: number }>
}

/** The file's next metadata, sealed: what a save sends with it. */
export interface SealedNextMetadata {
  metadataEnvelope: string
  metadataRevision: number
}

/**
 * Seals the file's next metadata (`change` applied to it as it is) and hands
 * it to `store`, which sends it with the save. When someone else's metadata
 * landed first, `change` is applied to theirs and the save sent again, once;
 * anything else is thrown as it came.
 */
export async function commitNextMetadata<T>(
  target: MetadataTarget,
  change: (metadata: FileMetadataV2) => FileMetadataV2,
  store: (metadata: SealedNextMetadata) => Promise<T>,
): Promise<T> {
  const { fileId, generation } = target.context
  const attempt = async (metadataRevision: number, metadata: FileMetadataV2): Promise<T> => {
    const next = change(metadata)
    const sealed = await renameFileRecordV1({ id: fileId, keyGeneration: generation, metadataRevision }, target.fileKey, next)
    const result = await store(sealed)
    target.file = { ...target.file, metadataRevision: sealed.metadataRevision, metadata: next }
    await acceptFileMetadata(fileId, sealed.metadataRevision).catch(() => undefined)
    return result
  }
  const base = target.file.metadata
  if (!base) throw new Error('file is not open')
  let current: CurrentMetadata | null
  try {
    return await attempt(target.file.metadataRevision, base)
  } catch (error) {
    if (!(error instanceof MetadataConflictError)) throw error
    current = error.current
    if (!current && target.reread) {
      const row = await target.reread()
      if (row.keyGeneration !== generation) throw new Error('the file key changed since')
      current = row
    }
    if (!current) throw error
  }
  // Older than this device has seen of the file: refused (RevisionGuard).
  await acceptFileMetadata(fileId, current.metadataRevision)
  const theirs = await openFileMetadataV1(
    { id: fileId, keyGeneration: generation, metadataRevision: current.metadataRevision, metadataEnvelope: current.metadataEnvelope },
    target.fileKey,
  )
  return attempt(current.metadataRevision, theirs)
}

/**
 * How a note's or place list's saved state commits (the collaboration
 * session's `commitState`): with the file's next metadata naming it as the
 * saved state (`stateRevisionId`), so a reader asks for that state and
 * refuses any other.
 */
export function stateCommitter(target: MetadataTarget) {
  return <T>(revisionId: string, store: (metadata: SealedNextMetadata) => Promise<T>): Promise<T> =>
    commitNextMetadata(target, (metadata) => ({ ...metadata, stateRevisionId: revisionId }), store)
}

/** A listed file as a save commits on top of it (null: its key or metadata did not open). */
export function metadataTargetOf(file: DriveFile): MetadataTarget | null {
  if (!file.fileKey || !file.content || !file.name) return null
  return {
    fileKey: file.fileKey,
    context: { fileId: file.id, generation: file.keyGeneration },
    file: { collectionId: file.collectionId, metadataRevision: file.metadataRevision, metadata: fileMetadataOf(file) },
  }
}

/** A listed file's `stateCommitter` (undefined: it did not open, so nothing it saves commits). */
export function stateCommitterOf(file: DriveFile): ReturnType<typeof stateCommitter> | undefined {
  const target = metadataTargetOf(file)
  return target ? stateCommitter(target) : undefined
}
