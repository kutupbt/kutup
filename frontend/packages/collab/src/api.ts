import axios from 'axios'
import api from '@kutup/session/client'
import { QuotaExceededError } from '@kutup/session/errors'

export interface VersionRow {
  id: string
  storagePath: string
  seqAtSnapshot: number
  docKeyId: number
  authorUserId: string
  sizeBytes: number
  label: string | null
  keepForever: boolean
  createdAt: string
  /** `file`: the whole file; `yjs`: a note's collaboration state. */
  kind: 'file' | 'yjs'
  /** The generation of the file key it was sealed under (docs/plans/drive-move.md). */
  keyGeneration: number
  /** Saved by someone on another server (`user@server`); the owner is `authorUserId` then. */
  remoteAuthor?: string
  /** A whole-file version: the version it replaced (`null`: the original upload, or not recorded). */
  parentVersionId?: string | null
}

/**
 * Where a file's collaboration calls go, under the API: `/files/:id` here;
 * for a file on another server, its route through this server
 * (docs/plans/collab-federation.md), which takes the same suffixes.
 */
export const localBase = (fileId: string) => `/files/${fileId}`

/**
 * The newest version holding collaboration state (`kind` `yjs`), from a
 * newest-first list: what a note, code file or place list opens from. A
 * whole-file version among them (a Replace, which those files are not
 * offered, or anything else) is never decoded as Yjs; with none, the file
 * opens from its original upload.
 */
export function newestYjsVersion(versions: readonly VersionRow[]): VersionRow | undefined {
  return versions.find((v) => v.kind === 'yjs')
}

export async function listVersions(fileId: string, base = localBase(fileId)): Promise<VersionRow[]> {
  const r = await api.get<VersionRow[]>(`${base}/versions`)
  return r.data
}

export function getVersionDownloadUrl(fileId: string, vid: string, base = localBase(fileId)): string {
  // Includes /api prefix because this URL is consumed directly (e.g. anchor href),
  // not via the axios instance which adds the baseURL itself.
  return `/api${base}/versions/${vid}/download`
}

export async function patchVersion(
  fileId: string,
  vid: string,
  patch: { label?: string; keepForever?: boolean },
  base = localBase(fileId),
): Promise<VersionRow> {
  const r = await api.patch<VersionRow>(`${base}/versions/${vid}`, patch)
  return r.data
}

/** Deletes an earlier version for good (never a file's newest). */
export async function deleteVersion(fileId: string, vid: string, base = localBase(fileId)): Promise<void> {
  await api.delete(`${base}/versions/${vid}`)
}

/**
 * Claim the first-seeder slot for a fresh collab file. Server runs an
 * atomic UPDATE; exactly one caller for a given file ever gets
 * `committed: true`. Used by TextCollabEditor's cold-start to avoid two
 * tabs both inserting `initialContent` and CRDT-merging into duplicate.
 *
 * Idempotent — once committed, all later callers (including from new
 * tab sessions) see committed=false and must wait for WS replay to
 * populate their local Y.Text.
 */
export async function claimSeed(fileId: string, base = localBase(fileId)): Promise<{ committed: boolean }> {
  const r = await api.post<{ committed: boolean }>(`${base}/claim-seed`)
  return r.data
}

export interface NewVersion {
  /** `file`: the whole file (office, whiteboard, restored copy); `yjs`: a note's state. */
  kind: 'file' | 'yjs'
  seqAtSnapshot: number
  docKeyId: number
  label?: string | null
  keepForever?: boolean
  /**
   * A conditional save (docs/plans/pass.md): stored only if the file still
   * holds this version (an id, or `original`); otherwise
   * {@link VersionConflictError}.
   */
  basedOn?: string
}

/** A conditional save lost: the file holds `current` now (a version id, or `original`). */
export class VersionConflictError extends Error {
  constructor(readonly current: string) {
    super('the file changed since')
    this.name = 'VersionConflictError'
  }
}

/**
 * POST /files/:fileId/versions — store a sealed version in one request
 * (docs/plans/drive-versions-v2.md). The server measures and charges what
 * arrives. A 413 (storage quota exceeded) becomes a typed
 * {@link QuotaExceededError}: notes' autosave disarms itself, explicit saves
 * and restores show a localized toast.
 */
export async function createVersion(
  fileId: string,
  sealed: Uint8Array,
  version: NewVersion,
  base = localBase(fileId),
): Promise<VersionRow> {
  const form = new FormData()
  form.append('kind', version.kind)
  form.append('seqAtSnapshot', String(version.seqAtSnapshot))
  form.append('docKeyId', String(version.docKeyId))
  form.append('keepForever', String(Boolean(version.keepForever)))
  if (version.label) form.append('label', version.label)
  if (version.basedOn) form.append('basedOn', version.basedOn)
  form.append('file', new Blob([sealed as BlobPart], { type: 'application/octet-stream' }), 'version')
  try {
    const r = await api.post<VersionRow>(`${base}/versions`, form)
    return r.data
  } catch (err) {
    if (axios.isAxiosError(err) && err.response?.status === 413) {
      throw new QuotaExceededError()
    }
    const body = axios.isAxiosError(err) ? (err.response?.data as { code?: string; current?: string } | undefined) : undefined
    if (axios.isAxiosError(err) && err.response?.status === 409 && body?.code === 'version_conflict' && body.current) {
      throw new VersionConflictError(body.current)
    }
    throw err
  }
}
