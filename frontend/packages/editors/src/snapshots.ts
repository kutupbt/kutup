import { createVersion } from '@kutup/collab/api'
import { decryptFileBlobV1, encryptFileBlobV1, type FileBlobContextV1 } from '@kutup/crypto/fileBlob'
import api from '@kutup/session/client'

/**
 * Whole-file versions, for the editors that save the entire file each time
 * (office documents, whiteboards). Notes save Yjs state through their own
 * SnapshotTrigger instead.
 *
 * A version is sealed exactly like the upload — same key, same object
 * binding — so downloads can stream it the same way (see ./content).
 */
export interface SnapshotTarget {
  fileKey: Uint8Array
  context: FileBlobContextV1
}

/**
 * Where a live editor is in the collaboration log: every edit up to `seq`
 * is in what it saves, under the document key `docKeyId`.
 */
export interface LogPosition {
  seq: number
  docKeyId: number
}

export async function saveSnapshot(
  target: SnapshotTarget,
  bytes: Uint8Array,
  opts: { label?: string; keepForever?: boolean; position?: LogPosition | null } = {},
): Promise<{ id: string; seqAtSnapshot: number }> {
  const sealed = await encryptFileBlobV1(bytes, target.fileKey, target.context)
  // The whole file, sealed like the upload: downloads serve it as the file.
  const version = await createVersion(target.context.fileId, sealed, {
    kind: 'file',
    // The office editor's edits up to here are in these bytes: the server
    // trims its log to this point, and whoever opens this version resumes
    // after it (a PDF's edits name its objects, so replaying ones it already
    // holds would change it again). Whiteboards keep no log: 0.
    seqAtSnapshot: opts.position?.seq ?? 0,
    docKeyId: opts.position?.docKeyId ?? 1,
    label: opts.label ?? null,
    keepForever: Boolean(opts.keepForever),
  })
  // The position as the server recorded it (never past its log's head).
  return { id: version.id, seqAtSnapshot: version.seqAtSnapshot }
}

/** A version's plaintext. */
export async function loadVersionBytes(target: SnapshotTarget, path: string): Promise<Uint8Array> {
  const { data } = await api.get<ArrayBuffer>(path, { responseType: 'arraybuffer' })
  return decryptFileBlobV1(new Uint8Array(data), target.fileKey, target.context)
}
