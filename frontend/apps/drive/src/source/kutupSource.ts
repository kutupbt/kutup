// Kutup's DriveSource (docs/plans/drive-source.md): drive-core's own hooks,
// unchanged, so every query key and invalidation stays as it is.
//
// The views are what Kutup's objects already are (a Folder is a FolderView, a
// DriveFile a FileView, a TrashEntry a TrashedView), and in Kutup the screens
// only ever hold objects drive-core gave them. So the hooks take Kutup's own
// types back: the casts below say that, nothing is converted.

import type { DriveSource } from '@kutup/drive-source/source'
import { useFolderFiles } from '@kutup/drive-core/files'
import { useFolders } from '@kutup/drive-core/folders'
import { useCreateFolder, useRenameFile, useRenameFolder, useSetFolderColor, useTrashFile, useTrashFolder } from '@kutup/drive-core/mutations'
import { useEmptyTrash, usePurge, useRestore, useTrash } from '@kutup/drive-core/trash'

export const kutupDriveSource: DriveSource = {
  capabilities: {
    folderColors: true,
  },

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
}
