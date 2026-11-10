import { createVersion, type VersionRow } from '@kutup/collab/api'
import {
  newRevisionId,
  openDriveObject,
  openFileMetadataV1,
  renameFileRecordV1,
  sealDriveFile,
  type DriveObjectExpected,
  type FileMetadataV2,
} from '@kutup/crypto'
import type { DriveFileBinding } from '@kutup/drive-core/keyring'
import { acceptFileMetadata } from '@kutup/drive-core/metadataGuard'
import { conflictCode, currentFileRow, manifestSigner } from '@kutup/files/upload/commit'
import api from '@kutup/session/client'

/**
 * Whole-file versions, for the editors that save the entire file each time
 * (office documents, whiteboards, Pass vaults). Notes save Yjs state through
 * their own SnapshotTrigger instead.
 *
 * A version is a revision in the block format (docs/plans/drive-block-format.md
 * §2), sealed under the file's current key for a new revision id, which
 * becomes the version's id. It becomes the file's current content: the
 * file's next metadata, committing to it, goes in the same request.
 */
export interface SnapshotTarget {
  /** The file's current key, and the file and generation it seals for. */
  fileKey: Uint8Array
  context: DriveFileBinding
  /**
   * The file as last known: its folder (to read it again), its metadata
   * revision and metadata (null when it did not open). Each save moves it on.
   */
  file: { collectionId: string; metadataRevision: number; metadata: FileMetadataV2 | null }
}

/**
 * Where a live editor is in the collaboration log: every edit up to `seq`
 * is in what it saves, under the document key `docKeyId`.
 */
export interface LogPosition {
  seq: number
  docKeyId: number
}

export interface FileVersionOptions {
  label?: string
  keepForever?: boolean
  position?: LogPosition | null
  /** Stored only while the file still holds this version (an id, or `original`). */
  basedOn?: string
}

/**
 * Seals `bytes` as a new revision and stores it as the file's content, with
 * the file's next metadata. When someone else's change to the metadata
 * landed meanwhile (`409 revision_conflict`), the file is read again and the
 * metadata sealed on top of it, once; anything else is thrown as it came.
 */
export async function saveFileVersion(target: SnapshotTarget, bytes: Uint8Array, opts: FileVersionOptions = {}): Promise<VersionRow> {
  const { fileId, generation } = target.context
  const base = target.file.metadata
  if (!base) throw new Error('file is not open')
  const revisionId = newRevisionId()
  const sealed = await sealDriveFile(bytes, target.fileKey, { fileId, revisionId, generation }, manifestSigner())
  const next = (metadata: FileMetadataV2): FileMetadataV2 => {
    // New content: its size and commitment; the old content's hash no longer holds.
    const { sha256: _sha256, ...kept } = metadata
    void _sha256
    return { ...kept, size: bytes.length, content: sealed.content }
  }
  const store = async (metadataRevision: number, metadata: FileMetadataV2) => {
    const commit = await renameFileRecordV1({ id: fileId, keyGeneration: generation, metadataRevision }, target.fileKey, next(metadata))
    const version = await createVersion(fileId, sealed.bytes, {
      kind: 'file',
      // The office editor's edits up to here are in these bytes: the server
      // trims its log to this point, and whoever opens this version resumes
      // after it (a PDF's edits name its objects, so replaying ones it already
      // holds would change it again). Whiteboards and vaults keep no log: 0.
      seqAtSnapshot: opts.position?.seq ?? 0,
      docKeyId: opts.position?.docKeyId ?? 1,
      label: opts.label ?? null,
      keepForever: Boolean(opts.keepForever),
      basedOn: opts.basedOn,
      revisionId,
      metadata: commit,
    })
    target.file = { ...target.file, metadataRevision: commit.metadataRevision, metadata: next(metadata) }
    await acceptFileMetadata(fileId, commit.metadataRevision).catch(() => undefined)
    return version
  }
  try {
    return await store(target.file.metadataRevision, base)
  } catch (error) {
    if (conflictCode(error) !== 'revision_conflict') throw error
  }
  // Renamed (or otherwise changed) meanwhile: keep what it says now.
  const row = await currentFileRow(target.file.collectionId, fileId)
  if (row.keyGeneration !== generation) throw new Error('the file key changed since')
  const current = await openFileMetadataV1(row, target.fileKey)
  return store(row.metadataRevision, current)
}

export async function saveSnapshot(
  target: SnapshotTarget,
  bytes: Uint8Array,
  opts: { label?: string; keepForever?: boolean; position?: LogPosition | null } = {},
): Promise<{ id: string; seqAtSnapshot: number }> {
  const version = await saveFileVersion(target, bytes, opts)
  // The position as the server recorded it (never past its log's head).
  return { id: version.id, seqAtSnapshot: version.seqAtSnapshot }
}

/** A stored object's plaintext, opened against what it must be (a version by its id, or the current content). */
export async function loadVersionBytes(
  opened: { fileKey: Uint8Array; expected: DriveObjectExpected },
  path: string,
): Promise<Uint8Array> {
  const { data } = await api.get<ArrayBuffer>(path, { responseType: 'arraybuffer' })
  return openDriveObject(new Uint8Array(data), opened.fileKey, opened.expected)
}
