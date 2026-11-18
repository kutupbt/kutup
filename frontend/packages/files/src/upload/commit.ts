// The commit of an uploaded revision (docs/plans/drive-block-format.md §10
// slice 3, "The commit, as Proton's"). A block-format upload lands as an
// uploaded revision; the file's next metadata, committing to that revision
// and its manifest's digest (known only after the last block), makes it
// current: `POST /api/v1/drive/files/{id}/revisions/{revisionId}/commit`.

import { manifestSignerOf, type ManifestSigner } from '@kutup/crypto'
import api from '@kutup/session/client'
import type { FileRow } from '@kutup/session/api-types'
import { getSession } from '@kutup/session/store'

/** Who signs a revision's manifest: the signed-in account (its Drive signing key and incarnation, from the identity root). */
export async function manifestSigner(): Promise<ManifestSigner> {
  const session = getSession()
  if (!session) throw new Error('not signed in')
  return manifestSignerOf(session.roots.identityRoot, session.accountId)
}

/** The file's next metadata, sealed at `metadataRevision`. */
export interface SealedMetadata {
  metadataEnvelope: string
  metadataRevision: number
}

/** The `code` of a 409 from the server, or null. */
export function conflictCode(error: unknown): string | null {
  const response = (error as { response?: { status?: number; data?: unknown } } | null)?.response
  if (response?.status !== 409) return null
  const code = (response.data as { code?: unknown } | undefined)?.code
  return typeof code === 'string' ? code : null
}

/** The file's row as it is now, from its folder's listing (there is no route for one file). */
export async function currentFileRow(collectionId: string, fileId: string): Promise<FileRow> {
  const { data } = await api.get<FileRow[]>(`/drive/collections/${collectionId}/files`)
  const row = data.find((candidate) => candidate.id === fileId)
  if (!row) throw new Error('the file is no longer in its folder')
  return row
}

export interface CommitOptions {
  fileId: string
  revisionId: string
  /** Seals the file's metadata as the next revision after `metadataRevision` (0 for a new file). */
  seal: (current: { metadataRevision: number; row: FileRow | null }) => Promise<SealedMetadata>
  /** The file's metadata revision the upload started from (0 for a new file). */
  metadataRevision: number
  /** Where to read the file's row again when someone committed meanwhile; null for a new file. */
  collectionId: string | null
  /**
   * What the revision is (`sealRevisionContent`: its id, manifest digest and
   * size under the file key it was sealed with), kept with it so it opens
   * against a committed digest once it is in the history.
   */
  revisionContentEnvelope: string
  /** A new file's name hash, when it commits under another name than its upload started with. */
  nameHash?: string
}

/**
 * Makes an uploaded revision current. A `409 revision_conflict` (someone
 * else's commit or rename landed meanwhile) re-reads the file and seals the
 * metadata again on top of it, once; `alreadyCommitted` (an interrupted
 * commit that took effect) is success. Anything else is thrown.
 */
export async function commitRevision(opts: CommitOptions): Promise<void> {
  const post = (sealed: SealedMetadata) =>
    api.post(`/drive/files/${opts.fileId}/revisions/${opts.revisionId}/commit`, {
      ...sealed,
      revisionContentEnvelope: opts.revisionContentEnvelope,
      ...(opts.nameHash ? { nameHash: opts.nameHash } : {}),
    })
  try {
    await post(await opts.seal({ metadataRevision: opts.metadataRevision, row: null }))
    return
  } catch (error) {
    const code = conflictCode(error)
    if (code === 'alreadyCommitted') return
    if (code !== 'revision_conflict' || !opts.collectionId) throw error
  }
  const row = await currentFileRow(opts.collectionId, opts.fileId)
  try {
    await post(await opts.seal({ metadataRevision: row.metadataRevision, row }))
  } catch (error) {
    if (conflictCode(error) === 'alreadyCommitted') return
    throw error
  }
}
