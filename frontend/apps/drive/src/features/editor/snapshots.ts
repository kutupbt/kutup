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

export async function saveSnapshot(
  target: SnapshotTarget,
  bytes: Uint8Array,
  opts: { label?: string; keepForever?: boolean } = {},
): Promise<string> {
  const sealed = await encryptFileBlobV1(bytes, target.fileKey, target.context)
  // The whole file, sealed like the upload: downloads serve it as the file.
  const version = await createVersion(target.context.fileId, sealed, {
    kind: 'file',
    // Whole-file editors have no update log to resume from.
    seqAtSnapshot: 0,
    docKeyId: 1,
    label: opts.label ?? null,
    keepForever: Boolean(opts.keepForever),
  })
  return version.id
}

/** A version's plaintext. */
export async function loadVersionBytes(target: SnapshotTarget, path: string): Promise<Uint8Array> {
  const { data } = await api.get<ArrayBuffer>(path, { responseType: 'arraybuffer' })
  return decryptFileBlobV1(new Uint8Array(data), target.fileKey, target.context)
}
