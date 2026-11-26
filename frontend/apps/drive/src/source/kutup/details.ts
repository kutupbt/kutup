// Kutup's side of an item's details (Proton Drive's DetailsModal): who made and
// last saved it as Kutup knows people, what it takes sealed, its history, and
// the check of the signature on what it holds now
// (docs/plans/drive-identity-pins.md). The details dialog asks for these
// through the source.

import { useQuery } from '@tanstack/react-query'
import type { AccountRef } from '@kutup/crypto/accountRef'
import { useAccountName } from '@kutup/drive-core/accountName'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import { fileLocation, type DriveFile, type Folder } from '@kutup/drive-core/model'
import { personOf, personOfAccount, usePeople } from '@kutup/drive-core/people'
import type { ClaimedAuthor } from '@kutup/drive-core/revisionAuthors'
import { sharedByMeRowOf, useSharedByMeRows } from '@kutup/drive-core/sharedByMe'
import type { FileDetailsInfo, FileView, FolderView, PersonLookup, SharingSummary } from '@kutup/drive-source/source'
import { fileHistory, holdsYjsState, listVersions, ORIGINAL, type HistoryEntry } from '@kutup/editors/history'

/** A digest as the metadata keeps it (base64), as `sha256sum` prints it; null when it is not one. */
function hexOfBase64(value: string): string | null {
  try {
    return Array.from(atob(value), (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
  } catch {
    return null
  }
}

/** The revision a history entry is (the original upload's is named by the metadata). */
export function revisionOf(file: DriveFile, entry: HistoryEntry): string | null {
  return entry.id === ORIGINAL ? file.originalRevisionId : entry.id
}

/** Who the history says saved an entry, as the signature must agree. */
export function claimOf(file: DriveFile, entry: HistoryEntry | undefined): ClaimedAuthor | null {
  if (!entry) return null
  if (entry.id === ORIGINAL) return file.uploaderAccountId ? { accountId: file.uploaderAccountId } : null
  // Someone on another server is named by their server's id there, which the pins can't compare: no claim.
  if (entry.remoteAuthor) return null
  return entry.authorAccountId ? { accountId: entry.authorAccountId } : null
}

/** The file's history here, asked again on every open: a replace or an editor's save adds versions without telling this query. */
export function useHistory(folder: Folder, file: DriveFile) {
  // The history is this server's: a file on another server has none here.
  const local = fileLocation(folder).kind === 'local'
  const versions = useQuery({
    queryKey: ['versions', file.id],
    queryFn: () => listVersions(file.id),
    enabled: local && Boolean(file.fileKey),
    refetchOnMount: 'always',
  })
  const history = versions.data ? fileHistory(file, versions.data) : null
  return { local, versions, history, current: history?.find((e) => e.current) }
}

/** Someone named by their permanent id: their profile name once they gave it, else their address. */
function usePersonOfAccount(account: AccountRef | null): PersonLookup | null {
  const address = useAccountName(account)
  const people = usePeople()
  if (!account) return null
  if (address.isPending) return 'pending'
  if (!address.data) return 'unknown'
  return { name: personOfAccount(people.data, account, address.data).name, address: address.data }
}

export function useKutupFileDetails(folderView: FolderView, fileView: FileView): FileDetailsInfo {
  const folder = folderView as Folder
  const file = fileView as DriveFile
  const identity = useDriveIdentity()
  const server = identity.data?.accountRef.server
  const people = usePeople()
  const { history, current } = useHistory(folder, file)
  // People on this server are named by id; on another server only the owner is known by address.
  const accountRef = (accountId: string | null): AccountRef | null =>
    accountId && server && folder.source !== 'remote' ? { server, accountId } : null
  const creatorRef = accountRef(file.uploaderAccountId)
  const lastRef: AccountRef | null = current
    ? (current.remoteAuthor ?? accountRef(current.id === ORIGINAL ? file.uploaderAccountId : current.authorAccountId))
    : null
  const creator = usePersonOfAccount(creatorRef)
  const last = usePersonOfAccount(lastRef)
  const remoteOwnerUploaded = folder.source === 'remote' && file.uploaderAccountId === folder.ownerAccountId && folder.ownerAccount
  const lastIsCreator = !lastRef || (current?.remoteAuthor === null && lastRef.accountId === file.uploaderAccountId)
  const yjs = holdsYjsState(file.name)
  return {
    createdBy: creator ?? (remoteOwnerUploaded ? { name: personOf(people.data, folder.ownerAccount!).name, address: folder.ownerAccount! } : null),
    lastUploadedBy: lastIsCreator ? null : last,
    // What the current content takes on the server, sealed (Proton's "Size").
    storedSize: current && current.sizeBytes > 0 ? current.sizeBytes : null,
    versions: history ? history.length : null,
    // The upload's hash says what the content is only while the server's content hash stands.
    sha256: !yjs && file.sha256 && file.contentHash ? hexOfBase64(file.sha256) : null,
  }
}

export function useKutupFolderCreator(folderView: FolderView): PersonLookup {
  const folder = folderView as Folder
  const identity = useDriveIdentity()
  const people = usePeople()
  if (folder.source === 'owned') return identity.data ? { name: identity.data.account } : 'pending'
  return folder.ownerAccount ? { name: personOf(people.data, folder.ownerAccount).name, address: folder.ownerAccount } : 'unknown'
}

export function useKutupSharingSummary(folder: FolderView, file?: FileView): SharingSummary | null | undefined {
  const sharing = useSharedByMeRows()
  if (sharing.isPending) return undefined
  const row = sharedByMeRowOf(sharing.data, folder.id, file?.id)
  const folderRow = file ? sharedByMeRowOf(sharing.data, folder.id) : undefined
  return { people: row ? row.people + row.otherServers : 0, links: row?.links ?? 0, folderShared: Boolean(folderRow) && !folder.isRoot }
}
