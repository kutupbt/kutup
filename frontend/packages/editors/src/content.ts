import { listVersions } from '@kutup/collab/api'
import { decryptFileBlobV1 } from '@kutup/crypto/fileBlob'
import { fetchDecryptedChunks } from '@kutup/files/download/fetchDecrypt'
import { resolveApiBase } from '@kutup/session/apiBase'
import api, { freshAccessToken } from '@kutup/session/client'
import { sealedAt } from '@kutup/drive-core/keyring'
import { contentPath, fileLocation, remoteStatePath, type DriveFile, type FileLocation, type Folder } from '@kutup/drive-core/model'
import { fromBase64 } from '@kutup/crypto'
import { isListName, stateToListJson } from '@kutup/map/list'
import { editorKindFor, extensionOf } from '@kutup/drive-core/editorKind'

/**
 * What a file holds now. Editors never rewrite the upload: each save is a
 * new version beside it, so "the file" is its latest version when there is
 * one. Office documents and whiteboards save the whole file, sealed like the
 * upload; notes save their Yjs state, which has to be turned back into text.
 */
export type FileContent =
  | { kind: 'original' }
  /** The latest version's encrypted blob, under the API base, sealed under `keyGeneration`;
   *  the collaboration log up to `seqAtSnapshot` is in it. */
  | { kind: 'version'; path: string; versionId: string | null; keyGeneration: number; seqAtSnapshot: number }
  /** A note's current text, from the version `versionId`. */
  | { kind: 'plain'; bytes: Uint8Array; versionId: string }

/**
 * An office document at a given session base (docs/onlyoffice.md,
 * "Collaboration sessions"): a tab joining a live session loads the version
 * the session started from, not the latest save. `versionId` null: the
 * original upload.
 */
export async function contentAt(file: DriveFile, versionId: string | null): Promise<FileContent> {
  if (versionId === null) {
    return { kind: 'version', path: `/files/${file.id}/original`, versionId: null, keyGeneration: file.originalKeyGeneration, seqAtSnapshot: 0 }
  }
  const version = (await listVersions(file.id)).find((v) => v.id === versionId)
  if (!version) throw new Error('the session base version is gone')
  return { kind: 'version', path: `/files/${file.id}/versions/${version.id}/download`, versionId: version.id, keyGeneration: version.keyGeneration, seqAtSnapshot: version.seqAtSnapshot }
}

export async function currentContent(folder: Folder, file: DriveFile): Promise<FileContent> {
  const location = fileLocation(folder)
  if (location.kind !== 'local') return remoteContent(location, file)
  // A place list keeps its places as Yjs state, like a note its text.
  if (isListName(file.name)) return listContent(file)
  // A PDF edited in ONLYOFFICE saves whole-file versions like an office document.
  const kind = file.name ? (editorKindFor(file.name) ?? (extensionOf(file.name) === 'pdf' ? 'office' : null)) : null
  if (!kind || !file.fileKey) return { kind: 'original' }
  const versions = await listVersions(file.id)
  // Newest first.
  const latest = versions[0]
  if (!latest || latest.sizeBytes === 0) return { kind: 'original' }
  const path = `/files/${file.id}/versions/${latest.id}/download`
  if (kind !== 'text') return { kind: 'version', path, versionId: latest.id, keyGeneration: latest.keyGeneration, seqAtSnapshot: latest.seqAtSnapshot }

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

/** The file's current plaintext (its latest edit, for documents), as a Blob. */
export async function readFile(folder: Folder, file: DriveFile, signal?: AbortSignal): Promise<Blob> {
  if (!file.fileKey) throw new Error('file is not open')
  const content = await currentContent(folder, file)
  if (content.kind === 'plain') return new Blob([content.bytes as BlobPart], { type: file.mimeType })
  const base = await resolveApiBase()
  const url = content.kind === 'version' ? `${base}${content.path}` : `${base}${contentPath(fileLocation(folder), file.id)}`
  const parts: BlobPart[] = []
  const sealed = await sealedAt(file, content.kind === 'version' ? content.keyGeneration : file.contentKeyGeneration)
  for await (const { plain } of fetchDecryptedChunks(url, sealed.fileKey, sealed.context, await freshAccessToken(), signal)) {
    // Blobs, not one growing buffer: the browser may keep large ones on disk.
    parts.push(new Blob([plain as BlobPart]))
  }
  return new Blob(parts, { type: file.mimeType })
}
