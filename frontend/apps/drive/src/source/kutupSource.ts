// Kutup's DriveSource (docs/plans/drive-source.md): drive-core's own hooks,
// unchanged, so every query key and invalidation stays as it is.
//
// The views are what Kutup's objects already are (a Folder is a FolderView, a
// DriveFile a FileView, a TrashEntry a TrashedView), and in Kutup the screens
// only ever hold objects drive-core gave them. So the hooks take Kutup's own
// types back: the casts below say that, nothing is converted.

import type { DriveSource, UploadActions } from '@kutup/drive-source/source'
import { loadFolderFiles, useFolderFiles } from '@kutup/drive-core/files'
import { useFolders } from '@kutup/drive-core/folders'
import { useCreateFolder, useRenameFile, useRenameFolder, useSetFolderColor, useTrashFile, useTrashFolder } from '@kutup/drive-core/mutations'
import { useEmptyTrash, usePurge, useRestore, useTrash } from '@kutup/drive-core/trash'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { uploadOne, useUploadActions } from './kutup/uploads/useUploadActions'
import type { FolderIndex } from '@kutup/drive-core/folders'
import { useCopy } from './kutup/drive/useCopy'
import { moveRefusal, type MoveSource } from './kutup/drive/move'
import { useMove } from './kutup/drive/useMove'
import { thumbnailUrl } from '@kutup/drive-core/thumbnails'
import { getSession } from '@kutup/session/store'
import { backfill } from './kutup/thumbnails/backfill'
import { folderLocation } from '@kutup/drive-core/model'
import { downloadFile, downloadFolderZip, downloadSelectionZip, FsaRequiredError } from '@kutup/editors/files/downloads'
import { BlobDownloadTooLarge } from '@kutup/files/download/streamDownload'

/** Kutup's uploads (sealed, resumable, thumbnails drawn after) as the screens start them. */
function useKutupUploadActions(): UploadActions {
  const actions = useUploadActions()
  return {
    ...(actions as unknown as Omit<UploadActions, 'createFile'>),
    createFile: (folder, file) => uploadOne(folder as Folder, file),
  }
}

export const kutupDriveSource: DriveSource = {
  capabilities: {
    folderColors: true,
  },

  isOpen: (folder) => Boolean((folder as Folder).key),
  isFileOpen: (file) => Boolean((file as DriveFile).fileKey),
  // Files on another server are not offered their history.
  offersHistory: (folder) => folderLocation(folder).kind === 'local',
  namesIn: async (folder) => (await loadFolderFiles(folder as Folder)).flatMap((f) => (f.name ? [f.name] : [])),

  useFolders,
  useFolderFiles: useFolderFiles as DriveSource['useFolderFiles'],
  useTrash,

  useCreateFolder: useCreateFolder as unknown as DriveSource['useCreateFolder'],
  useRenameFolder: useRenameFolder as unknown as DriveSource['useRenameFolder'],
  useRenameFile: useRenameFile as unknown as DriveSource['useRenameFile'],
  useSetFolderColor: useSetFolderColor as unknown as DriveSource['useSetFolderColor'],
  useTrashFolder: useTrashFolder as unknown as DriveSource['useTrashFolder'],
  useTrashFile: useTrashFile as unknown as DriveSource['useTrashFile'],
  useRestore,
  usePurge,
  useEmptyTrash,

  useUploadActions: useKutupUploadActions,

  useCopy: useCopy as unknown as DriveSource['useCopy'],
  useMove: useMove as unknown as DriveSource['useMove'],
  downloadFile: (folder, file) => downloadFile(folder as Folder, file as DriveFile),
  downloadFolderZip: (folder, onProgress) => downloadFolderZip(folder as Folder, onProgress),
  downloadSelectionZip: (items, archive, onProgress) => downloadSelectionZip(items as MoveSource[], archive, onProgress),
  downloadFailure: (error) => (error instanceof FsaRequiredError ? 'zipTooLarge' : error instanceof BlobDownloadTooLarge ? 'fileTooLarge' : 'other'),

  thumbnail: async (folder, file, size) => {
    const url = await thumbnailUrl(file as DriveFile, size)
    // On screen: draw a missing or stale one in the background (docs/plans/drive-thumbnails.md).
    const session = getSession()
    if (session) backfill(folder as Folder, file as DriveFile, session.accountId)
    return url
  },
  thumbnailStamp: (file) => `${(file as DriveFile).thumbnails.sm ?? ''}:${String((file as DriveFile).thumbnailStale)}`,
  // A file by whoever can edit its folder, a folder by its owner (docs/plans/drive-move.md).
  mayMove: (item) => {
    const folder = item.folder as Folder
    if (item.file) return folder.source !== 'remote' && folder.canUpload && Boolean((item.file as DriveFile).fileKey)
    return folder.source === 'owned' && folder.canManage && !folder.isRoot && Boolean(folder.key)
  },
  moveRefusal: (tree, item, dest) => moveRefusal(tree as FolderIndex, item as MoveSource, dest as Folder),
}
