import { listVersions, newestYjsVersion } from '@kutup/collab/api'
import { fetchDecryptedChunks } from '@kutup/files/download/fetchDecrypt'
import { resolveApiBase } from '@kutup/session/apiBase'
import api, { freshAccessToken } from '@kutup/session/client'
import { currentContentOf, originalContentOf, relayedVersion, versionContentOf, type RelayedState } from '@kutup/drive-core/keyring'
import { contentPath, fileLocation, remoteStatePath, type DriveFile, type FileLocation, type Folder } from '@kutup/drive-core/model'
import { fromBase64, openDriveObject } from '@kutup/crypto'
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
  /** The latest version's encrypted blob, under the API base, sealed under `keyGeneration`,
   *  with its sealed content record (`versionId` null: the original upload, whose
   *  record comes with it); the collaboration log up to `seqAtSnapshot` is in it. */
  | {
      kind: 'version'
      path: string
      versionId: string | null
      keyGeneration: number
      seqAtSnapshot: number
      revisionContentEnvelope: string | null
    }
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
    return {
      kind: 'version',
      path: `/files/${file.id}/original`,
      versionId: null,
      keyGeneration: file.originalKeyGeneration,
      seqAtSnapshot: 0,
      revisionContentEnvelope: null,
    }
  }
  const version = (await listVersions(file.id)).find((v) => v.id === versionId)
  if (!version) throw new Error('the session base version is gone')
  return {
    kind: 'version',
    path: `/files/${file.id}/versions/${version.id}/download`,
    versionId: version.id,
    keyGeneration: version.keyGeneration,
    seqAtSnapshot: version.seqAtSnapshot,
    revisionContentEnvelope: version.revisionContentEnvelope,
  }
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
  // Newest first. A note opens from its newest Yjs state, never a stray
  // whole-file version; an office document or whiteboard from its newest.
  const latest = kind === 'text' ? newestYjsVersion(versions) : versions[0]
  if (!latest || latest.sizeBytes === 0) return { kind: 'original' }
  const path = `/files/${file.id}/versions/${latest.id}/download`
  if (kind !== 'text') {
    return {
      kind: 'version',
      path,
      versionId: latest.id,
      keyGeneration: latest.keyGeneration,
      seqAtSnapshot: latest.seqAtSnapshot,
      revisionContentEnvelope: latest.revisionContentEnvelope,
    }
  }

  const { data } = await api.get<ArrayBuffer>(path, { responseType: 'arraybuffer' })
  const opened = await versionContentOf(file, latest)
  const state = await openDriveObject(new Uint8Array(data), opened.fileKey, opened.expected)
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
  const latest = newestYjsVersion(await listVersions(file.id))
  if (!latest || latest.sizeBytes === 0) return { kind: 'original' }
  const { data } = await api.get<ArrayBuffer>(`/files/${file.id}/versions/${latest.id}/download`, { responseType: 'arraybuffer' })
  const opened = await versionContentOf(file, latest)
  const state = await openDriveObject(new Uint8Array(data), opened.fileKey, opened.expected)
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
  let saved: RelayedState
  try {
    saved = (await api.get<RelayedState>(path)).data
  } catch (error) {
    if ((error as { response?: { status?: number } }).response?.status === 404) return { kind: 'original' }
    throw error
  }
  // A saved state relayed from the other server: a note's snapshot, opened
  // against the sealed record that comes with it.
  const opened = await versionContentOf(file, relayedVersion(saved))
  const state = await openDriveObject(fromBase64(saved.state), opened.fileKey, opened.expected)
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

/** What a stored version opens against: its sealed record; the original upload, the one served with it. */
export function versionToOpen(file: DriveFile, content: Extract<FileContent, { kind: 'version' }>) {
  return content.versionId === null
    ? originalContentOf(file)
    : versionContentOf(file, { id: content.versionId, keyGeneration: content.keyGeneration, revisionContentEnvelope: content.revisionContentEnvelope })
}

/** The file's current plaintext (its latest edit, for documents), as a Blob. */
export async function readFile(folder: Folder, file: DriveFile, signal?: AbortSignal): Promise<Blob> {
  if (!file.fileKey) throw new Error('file is not open')
  const content = await currentContent(folder, file)
  if (content.kind === 'plain') return new Blob([content.bytes as BlobPart], { type: file.mimeType })
  const base = await resolveApiBase()
  const url = content.kind === 'version' ? `${base}${content.path}` : `${base}${contentPath(fileLocation(folder), file.id)}`
  const parts: BlobPart[] = []
  const opened = content.kind === 'version' ? await versionToOpen(file, content) : await currentContentOf(file)
  for await (const { plain } of fetchDecryptedChunks(url, opened.fileKey, opened.expected, await freshAccessToken(), signal)) {
    // Blobs, not one growing buffer: the browser may keep large ones on disk.
    parts.push(new Blob([plain as BlobPart]))
  }
  return new Blob(parts, { type: file.mimeType })
}
