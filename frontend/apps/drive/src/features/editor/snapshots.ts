import { recordSnapshot } from '@kutup/collab/api'
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

export async function saveSnapshot(
  target: SnapshotTarget,
  bytes: Uint8Array,
  opts: { label?: string; keepForever?: boolean } = {},
): Promise<string> {
  const fileId = target.context.fileId
  const sealed = await encryptFileBlobV1(bytes, target.fileKey, target.context)
  const form = new FormData()
  form.append('file', new Blob([sealed as BlobPart], { type: 'application/octet-stream' }), 'snapshot')
  const { data } = await api.post<{ s3VersionId: string; storagePath: string }>(
    `/files/${fileId}/snapshot-blob`,
    form,
  )
  const recorded = await recordSnapshot(fileId, {
    s3VersionId: data.s3VersionId,
    storagePath: data.storagePath,
    // Whole-file editors have no update log to resume from.
    seqAtSnapshot: 0,
    docKeyId: 1,
    sizeBytes: sealed.length,
    label: opts.label ?? null,
    keepForever: Boolean(opts.keepForever),
  })
  return recorded.id
}

/** A version's plaintext. */
export async function loadVersionBytes(target: SnapshotTarget, path: string): Promise<Uint8Array> {
  const { data } = await api.get<ArrayBuffer>(path, { responseType: 'arraybuffer' })
  return decryptFileBlobV1(new Uint8Array(data), target.fileKey, target.context)
}
