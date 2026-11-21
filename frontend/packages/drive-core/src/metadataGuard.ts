// Freshness of a file's sealed metadata (docs/plans/drive-block-format.md §2,
// "Freshness of the metadata itself"): each device remembers the highest
// metadata revision it has seen per file (`RevisionGuard`, as Pass, Mail,
// Calendar and the identity pins use it) and refuses an older one. Since the
// metadata commits to the current content, serving old metadata together
// with old content is refused on any device that saw newer.
//
// Without a signed-in account (a public link's page) there is no history to
// keep: the guard applies to accounts only.

import { revisionGuard } from '@kutup/crypto'
import { getSession } from '@kutup/session/store'

export const DRIVE_FILE_METADATA_SCOPE = 'drive-file-metadata'

/**
 * A file's metadata revision read (or written): rejects `OlderThanSeenError`
 * when this device has seen a newer one of the file; remembered when newer.
 */
export async function acceptFileMetadata(fileId: string, metadataRevision: number): Promise<void> {
  const session = getSession()
  if (!session) return
  await revisionGuard(session).accept(DRIVE_FILE_METADATA_SCOPE, fileId, metadataRevision)
}
