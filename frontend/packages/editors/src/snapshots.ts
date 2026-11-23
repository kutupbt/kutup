import { createVersion, type VersionRow } from '@kutup/collab/api'
import {
  newRevisionId,
  openDriveObject,
  sealDriveFile,
  resolveServed,
  REVISION_CONTENT_HEADER,
  REVISION_HEADER,
  type DriveObjectToOpen,
  type FileMetadataV2,
} from '@kutup/crypto'
import { commitNextMetadata, type MetadataTarget } from '@kutup/drive-core/metadataCommit'
import { currentFileRow, manifestSigner } from '@kutup/files/upload/commit'
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
export type SnapshotTarget = MetadataTarget

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
 * landed meanwhile (`409 revisionConflict`), the metadata is sealed again
 * on top of theirs (as the conflict gives it, or read again from the
 * file's folder), once; anything else is thrown as it came.
 */
export async function saveFileVersion(target: SnapshotTarget, bytes: Uint8Array, opts: FileVersionOptions = {}): Promise<VersionRow> {
  const { fileId, generation } = target.context
  if (!target.file.metadata) throw new Error('file is not open')
  const revisionId = newRevisionId()
  const sealed = await sealDriveFile(bytes, target.fileKey, { fileId, revisionId, generation }, await manifestSigner())
  const next = (metadata: FileMetadataV2): FileMetadataV2 => {
    // New content: its size and commitment; the old content's hash no longer holds.
    const { sha256: _sha256, ...kept } = metadata
    void _sha256
    return { ...kept, size: bytes.length, content: sealed.content }
  }
  // Read again from the file's folder when a conflict doesn't carry the metadata.
  const committing: SnapshotTarget = { ...target, reread: target.reread ?? (() => currentFileRow(target.file.collectionId, fileId)) }
  try {
    return await commitNextMetadata(committing, next, (metadata) =>
    createVersion(fileId, sealed.bytes, {
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
      revisionContentEnvelope: sealed.revisionContentEnvelope,
      metadata,
    }),
    )
  } finally {
    // Each commit moves the file on: the caller's copy too.
    target.file = committing.file
  }
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

/**
 * A stored object's plaintext, opened against what it must be: the current
 * content, a version by its id and sealed record, or the original upload by
 * the revision and record served with it.
 */
export async function loadVersionBytes(
  opened: { fileKey: Uint8Array; expected: DriveObjectToOpen },
  path: string,
): Promise<Uint8Array> {
  const response = await api.get<ArrayBuffer>(path, { responseType: 'arraybuffer' })
  const header = (name: string) => {
    const value: unknown = response.headers?.[name]
    return typeof value === 'string' && value ? value : null
  }
  const expected = await resolveServed(opened.fileKey, opened.expected, {
    revisionId: header(REVISION_HEADER),
    revisionContentEnvelope: header(REVISION_CONTENT_HEADER),
  })
  return openDriveObject(new Uint8Array(response.data), opened.fileKey, expected)
}
