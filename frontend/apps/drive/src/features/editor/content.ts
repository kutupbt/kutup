import { listVersions } from '@kutup/collab/api'
import { decryptFileBlobV1 } from '@kutup/crypto/fileBlob'
import api from '@kutup/session/client'
import { sealedAt } from '@kutup/drive-core/keyring'
import { fileLocation, remoteStatePath, type DriveFile, type FileLocation, type Folder } from '@kutup/drive-core/model'
import { fromBase64 } from '@kutup/crypto'
import { isListName, stateToListJson } from '@kutup/map/list'
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
  const location = fileLocation(folder)
  if (location.kind !== 'local') return remoteContent(location, file)
  // A place list keeps its places as Yjs state, like a note its text.
  if (isListName(file.name)) return listContent(file)
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

/** A place list's current places as list JSON (docs/plans/maps.md). */
async function listContent(file: DriveFile): Promise<FileContent> {
  if (!file.fileKey) return { kind: 'original' }
  const latest = (await listVersions(file.id))[0]
  if (!latest || latest.sizeBytes === 0) return { kind: 'original' }
  const { data } = await api.get<ArrayBuffer>(`/files/${file.id}/versions/${latest.id}/download`, { responseType: 'arraybuffer' })
  const sealed = await sealedAt(file, latest.keyGeneration)
  const state = await decryptFileBlobV1(new Uint8Array(data), sealed.fileKey, sealed.context)
  return { kind: 'plain', bytes: stateToListJson(state), versionId: latest.id }
}

/**
 * A file on another server: a note or place list as last saved (its state
 * relayed through this server), anything else as it is there.
 */
async function remoteContent(location: FileLocation, file: DriveFile): Promise<FileContent> {
  const list = isListName(file.name)
  const path = remoteStatePath(location, file.id)
  if (!path || !file.fileKey || (!list && (!file.name || editorKindFor(file.name) !== 'text'))) return { kind: 'original' }
  let saved: { keyGeneration: number; state: string }
  try {
    saved = (await api.get<{ keyGeneration: number; state: string }>(path)).data
  } catch (error) {
    if ((error as { response?: { status?: number } }).response?.status === 404) return { kind: 'original' }
    throw error
  }
  const sealed = await sealedAt(file, saved.keyGeneration)
  const state = await decryptFileBlobV1(fromBase64(saved.state), sealed.fileKey, sealed.context)
  if (list) return { kind: 'plain', bytes: stateToListJson(state), versionId: 'remote' }
  const Y = await import('yjs')
  const doc = new Y.Doc()
  try {
    Y.applyUpdateV2(doc, state)
    return { kind: 'plain', bytes: new TextEncoder().encode(doc.getText('content').toJSON()), versionId: 'remote' }
  } finally {
    doc.destroy()
  }
}
