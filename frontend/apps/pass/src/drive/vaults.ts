// Vaults are KeePass files in Drive (docs/plans/pass.md). This lists every
// one the account can open, reads exact versions of them, saves new
// versions only on top of the version they were made from, and makes new
// vault files.

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo } from 'react'
import { listVersions } from '@kutup/collab/api'
import { allFilesKey, loadAllFiles, loadFolderFiles } from '@kutup/drive-core/files'
import { isVaultName } from '@kutup/drive-core/editorKind'
import { useSharedFiles } from '@kutup/drive-core/fileShares'
import { foldersKey, useFolders } from '@kutup/drive-core/folders'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import { currentContentOf, originalContentOf, versionContentOf } from '@kutup/drive-core/keyring'
import { fileMetadataOf, type DriveFile, type Folder } from '@kutup/drive-core/model'
import { uploadUnderFreeName } from '@kutup/drive-core/names'
import { rekeyFile } from '@kutup/drive-core/rekey'
import { loadVersionBytes, saveFileVersion, type SnapshotTarget } from '@kutup/editors/snapshots'
import { streamUpload } from '@kutup/files/upload/streamUpload'
import { freshAccessToken } from '@kutup/session/client'

/** Names the original upload where a version id is expected. */
export const ORIGINAL = 'original'

export interface VaultFile {
  folder: Folder
  file: DriveFile
  /** The owner's account, when the vault is someone else's. */
  owner: string | null
  /** Whether this account may save it. */
  canEdit: boolean
}

export { isVaultName } from '@kutup/drive-core/editorKind'

/** A vault's name without `.kdbx`. */
export function vaultTitle(name: string | null | undefined): string {
  return (name ?? '').replace(/\.kdbx$/i, '')
}

/** Every vault the account can open: its own anywhere, in shared folders, and vaults shared by themselves. */
export function useVaultFiles() {
  const folders = useFolders()
  const sharedFiles = useSharedFiles()
  const identity = useDriveIdentity()
  const queryClient = useQueryClient()
  const listing = useQuery({
    queryKey: [...allFilesKey, identity.data?.accountId],
    enabled: Boolean(folders.data),
    queryFn: () => loadAllFiles(folders.data!.all, queryClient),
  })
  const vaults = useMemo(() => {
    const out: VaultFile[] = []
    const seen = new Set<string>()
    for (const folder of folders.data?.all ?? []) {
      for (const file of listing.data?.get(folder.id) ?? []) {
        if (!isVaultName(file.name) || seen.has(file.id)) continue
        seen.add(file.id)
        out.push({
          folder,
          file,
          owner: folder.source === 'owned' ? null : (folder.ownerAccount ?? null),
          canEdit: folder.source === 'owned' || folder.canUpload,
        })
      }
    }
    for (const shared of sharedFiles.data ?? []) {
      // Vaults on other servers, or still waiting for their owner's new key,
      // cannot be opened here yet.
      if (!isVaultName(shared.file.name) || seen.has(shared.file.id) || shared.container.remoteFileShareId) continue
      if (shared.state === 'waiting' || shared.state === 'gone') continue
      seen.add(shared.file.id)
      out.push({ folder: shared.container, file: shared.file, owner: shared.ownerAccount, canEdit: shared.canEdit })
    }
    out.sort((a, b) => (a.file.name ?? '').localeCompare(b.file.name ?? '', undefined, { numeric: true, sensitivity: 'base' }))
    return out
  }, [folders.data, listing.data, sharedFiles.data])
  return {
    root: folders.data?.root ?? null,
    folders: folders.data?.all ?? [],
    vaults,
    loading: folders.isPending || listing.isPending || sharedFiles.isPending,
    error: folders.error ?? listing.error ?? null,
  }
}

/** One version's contents (KDBX bytes): a version id, or {@link ORIGINAL}. */
export async function readVaultVersion(file: DriveFile, version: string): Promise<Uint8Array> {
  if (version === ORIGINAL) {
    // The upload, which the version list does not name: it opens against
    // the revision and sealed record served with it.
    return loadVersionBytes(await originalContentOf(file), `/drive/files/${file.id}/original`)
  }
  const row = (await listVersions(file.id)).find((v) => v.id === version)
  if (!row) throw new Error(`version ${version} is gone`)
  return loadVersionBytes(await versionContentOf(file, row), `/drive/files/${file.id}/versions/${row.id}/download`)
}

/** What the vault holds now, and which version that is. */
export async function readCurrentVault(file: DriveFile): Promise<{ contents: Uint8Array; version: string }> {
  const newest = (await listVersions(file.id)).find((v) => v.kind === 'file')
  if (newest) return { contents: await readVaultVersion(file, newest.id), version: newest.id }
  // Never saved: the upload is the file's content, opened against what its metadata commits to.
  return { contents: await loadVersionBytes(await currentContentOf(file), `/drive/files/${file.id}/download`), version: ORIGINAL }
}

/** The file as its folder lists it now (its key may have moved on). */
export async function refreshVaultFile(folder: Folder, file: DriveFile): Promise<DriveFile> {
  const listed = (await loadFolderFiles(folder)).find((f) => f.id === file.id)
  return listed ?? file
}

/**
 * Saves `contents` as a new version made from `basedOn`. Throws
 * `VersionConflictError` (from @kutup/collab/api) when the vault holds
 * another version now. Returns the new version's id and the file as it is
 * after (re-keyed first when its folder rotated since).
 */
export async function saveVaultVersion(
  folder: Folder,
  file: DriveFile,
  contents: Uint8Array,
  basedOn: string,
): Promise<{ version: string; file: DriveFile }> {
  const current = await rekeyFile(folder, file)
  if (!current.fileKey) throw new Error('file is not open')
  // The new content becomes the file's, with its next metadata (docs/plans/drive-block-format.md §2).
  const target: SnapshotTarget = {
    fileKey: current.fileKey,
    context: { fileId: current.id, generation: current.keyGeneration },
    file: { collectionId: current.collectionId, metadataRevision: current.metadataRevision, metadata: fileMetadataOf(current) },
  }
  const row = await saveFileVersion(target, contents, { basedOn })
  const metadata = target.file.metadata!
  return {
    version: row.id,
    // The file after: the next save commits on top of this metadata.
    file: {
      ...current,
      name: metadata.name,
      size: metadata.size,
      sha256: null,
      content: metadata.content,
      metadataRevision: target.file.metadataRevision,
      contentKeyGeneration: current.keyGeneration,
    },
  }
}

/** Makes a vault file `name`.kdbx in `folder` (under a free name); returns its id. */
export function useCreateVaultFile() {
  const queryClient = useQueryClient()
  return async (folder: Folder, name: string, contents: Uint8Array): Promise<string> => {
    if (!folder.key || !folder.canUpload) throw new Error('folder is not open')
    const key = folder.key
    const file = new File([contents as BlobPart], `${name}.kdbx`, { type: 'application/x-keepass2' })
    const uploaded = await uploadUnderFreeName(folder, file, (named, nameHash) =>
      streamUpload({
        file: named,
        collection: { id: folder.id, keyEpoch: folder.keyEpoch, collectionKey: key },
        accessToken: freshAccessToken,
        nameHash,
      }),
    )
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['files'] }),
      queryClient.invalidateQueries({ queryKey: foldersKey }),
    ])
    return uploaded.fileId
  }
}
