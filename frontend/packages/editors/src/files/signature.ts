// Who signed what a file holds now, for Drive's details dialog (Proton
// Drive's "Digital signature verified" banner in `FileDetailsModalView`).
// Every block-format revision's manifest is signed by its uploader
// (docs/plans/drive-block-format.md §2); opening the current content's
// header, trailer and manifest (HTTP Range, no block) is enough to check it
// against the identity pins, as every open does (`manifestSigners`).

import type { ClaimedAuthor } from '@kutup/drive-core/revisionAuthors'
import { driveIdentityOf } from '@kutup/drive-core/identity'
import { manifestSignerVerdict, type ManifestSignerVerdict } from '@kutup/drive-core/manifestSigners'
import { currentContentOf } from '@kutup/drive-core/keyring'
import { contentPath, fileLocation, type DriveFile, type Folder } from '@kutup/drive-core/model'
import { openBlockReader } from '@kutup/files/blockReader/client'
import { DEFAULT_STREAM_LIMITS } from '@kutup/files/stream/limits'
import { resolveApiBase } from '@kutup/session/apiBase'
import { freshAccessToken } from '@kutup/session/client'
import { getSession } from '@kutup/session/store'
import { currentContent, versionToOpen } from '../content'

export interface ContentSignature {
  /** The revision whose manifest was checked. */
  revisionId: string
  verdict: ManifestSignerVerdict
  /** Who the history says saved it (null: it names nobody), whom a good signature is then by. */
  claimed: ClaimedAuthor | null
}

/**
 * The signature on `file`'s current content, checked against the pins and
 * against `claimed` (who the history shows saved that revision). Null when
 * there is nothing to check here: a note's or place list's saved state
 * (checked as its editor opens it), a revision without a signer, or no
 * session. Only the manifest is read; no block is fetched.
 */
export async function currentContentSignature(
  folder: Folder,
  file: DriveFile,
  claimed: (revisionId: string) => ClaimedAuthor | null,
  signal?: AbortSignal,
): Promise<ContentSignature | null> {
  const session = getSession()
  if (!session || !file.fileKey) return null
  const content = await currentContent(folder, file)
  if (content.kind === 'plain') return null
  const base = await resolveApiBase()
  const url = content.kind === 'version' ? `${base}${content.path}` : `${base}${contentPath(fileLocation(folder), file.id)}`
  const opened = content.kind === 'version' ? await versionToOpen(file, content) : await currentContentOf(file)
  const reader = await openBlockReader({
    source: { family: 'drive', url, fileKey: opened.fileKey, expected: opened.expected },
    accessToken: () => freshAccessToken(),
    settings: { cacheBlocks: 1, readaheadBlocks: 0, responseMaxBytes: DEFAULT_STREAM_LIMITS.responseMaxBytes },
    signal,
  })
  try {
    const { signer, fileId, revisionId } = reader.opened
    if (!signer) return null
    const author = claimed(revisionId)
    const verdict = await manifestSignerVerdict(
      await driveIdentityOf(session),
      { fileId, revisionId, accountId: signer.accountId, incarnationId: signer.incarnationId, signedBy: (key) => reader.signedBy(key) },
      author,
    )
    return { revisionId, verdict, claimed: author }
  } finally {
    reader.close()
  }
}
