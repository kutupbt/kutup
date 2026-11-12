// Who the UI shows as a revision's author (docs/plans/drive-block-format.md
// §2, "The signature"): a version row's author, the original upload's
// uploader, as the server's history says. Recorded before the revision
// opens, so its manifest's signer is checked against it (`manifestSigners`).

/**
 * Who the server says wrote a revision, as the UI shows it: a version
 * row's author (`authorUserId`, or `remoteAuthor` for someone on another
 * server), the original upload's uploader. The signature must agree.
 */
export type ClaimedAuthor = { accountId: string } | { address: string }

/** The authors the UI shows, by file and revision: what each opened revision's signer is compared with. */
const claims = new Map<string, ClaimedAuthor>()
const MAX_CLAIMS = 5000

/**
 * Records who the UI shows as a revision's author (a version row's, the
 * original upload's uploader) before it opens, so the signer is checked
 * against it. The newest claim for a revision wins.
 */
export function claimRevisionAuthor(fileId: string, revisionId: string, author: ClaimedAuthor | null): void {
  if (!author) return
  const key = `${fileId}/${revisionId}`
  claims.delete(key)
  claims.set(key, author)
  // Oldest first: a long session forgets the oldest claims.
  while (claims.size > MAX_CLAIMS) claims.delete(claims.keys().next().value as string)
}

/** A version row's author as the UI shows it: someone on another server by address, else the account. */
export function versionAuthor(version: { authorUserId?: string | null; remoteAuthor?: string | null }): ClaimedAuthor | null {
  if (version.remoteAuthor) return { address: version.remoteAuthor }
  return version.authorUserId ? { accountId: version.authorUserId } : null
}

/** The author the UI shows for a revision (null: none recorded). */
export function claimedAuthorOf(fileId: string, revisionId: string): ClaimedAuthor | null {
  return claims.get(`${fileId}/${revisionId}`) ?? null
}
