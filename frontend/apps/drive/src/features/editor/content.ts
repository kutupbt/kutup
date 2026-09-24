import { listVersions } from '@kutup/collab/api'
import { decryptFileBlobV1 } from '@kutup/crypto/fileBlob'
import api from '@kutup/session/client'
import { sealedAt } from '../drive/keyring'
import type { DriveFile, Folder } from '../drive/model'
import { editorKindFor } from './editorKind'

/**
 * What a file holds now. Editors never rewrite the upload: each save is a
 * new version beside it, so "the file" is its latest version when there is
 * one. Office documents and whiteboards save the whole file, sealed like the
 * upload; notes save their Yjs state, which has to be turned back into text.
 */
export type FileContent =
  | { kind: 'original' }
  /** The latest version's encrypted blob, under the API base, sealed under `keyGeneration`. */
  | { kind: 'version'; path: string; versionId: string; keyGeneration: number }
  /** A note's current text, from the version `versionId`. */
  | { kind: 'plain'; bytes: Uint8Array; versionId: string }

export async function currentContent(folder: Folder, file: DriveFile): Promise<FileContent> {
  const kind = file.name ? editorKindFor(file.name) : null
  if (!kind || !file.fileKey) return { kind: 'original' }
  const versions = await listVersions(file.id)
  // Newest first.
  const latest = versions[0]
  if (!latest || latest.sizeBytes === 0) return { kind: 'original' }
  const path = `/files/${file.id}/versions/${latest.id}/download`
  if (kind !== 'text') return { kind: 'version', path, versionId: latest.id, keyGeneration: latest.keyGeneration }

  const { data } = await api.get<ArrayBuffer>(path, { responseType: 'arraybuffer' })
  const sealed = await sealedAt(file, latest.keyGeneration)
  const state = await decryptFileBlobV1(new Uint8Array(data), sealed.fileKey, sealed.context)
  const Y = await import('yjs')
  const doc = new Y.Doc()
  try {
    Y.applyUpdateV2(doc, state)
    return { kind: 'plain', bytes: new TextEncoder().encode(doc.getText('content').toJSON()), versionId: latest.id }
  } finally {
    doc.destroy()
  }
}
