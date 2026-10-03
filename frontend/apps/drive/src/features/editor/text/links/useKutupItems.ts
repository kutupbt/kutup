import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { useSharedFiles } from '@kutup/drive-core/fileShares'
import type { ItemKind } from '@kutup/drive-core/kinds'
import type { FolderIndex } from '@kutup/drive-core/folders'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { useDriveIndex } from '../../../search/useDriveIndex'

/** An item a note can link to, as this reader sees it. */
export interface KutupItem {
  type: 'file' | 'folder'
  id: string
  name: string
  kind: ItemKind
  /** The folder a file is in (or the folder itself). */
  folder: Folder
  file?: DriveFile
  /** Where it is, for the picker: "My files / Trips". */
  where: string
}

export interface KutupItems {
  byId: Map<string, KutupItem>
  /** Everything, folders first then files, for the picker. */
  all: KutupItem[]
  ready: boolean
}

function folderName(folder: Folder, myFiles: string): string {
  return folder.isRoot ? myFiles : folder.name ?? ''
}

function pathOf(index: FolderIndex | undefined, folder: Folder, myFiles: string): string {
  const names: string[] = []
  let at: Folder | undefined = folder
  for (let depth = 0; at && depth < 32; depth++) {
    names.unshift(folderName(at, myFiles))
    at = at.parentId ? index?.byId.get(at.parentId) : undefined
  }
  return names.filter(Boolean).join(' / ')
}

/**
 * Every folder and file this reader can see, by id: Drive's search index
 * (folders and their files, decrypted here) and the files shared with them
 * on their own. Loaded only while `enabled`.
 */
export function useKutupItems(enabled: boolean): KutupItems {
  const { t } = useTranslation()
  const drive = useDriveIndex(enabled)
  const shared = useSharedFiles({ enabled })
  const myFiles = t('nav.myFiles')
  const sharedWithMe = t('nav.shared')
  return useMemo(() => {
    const byId = new Map<string, KutupItem>()
    const folders: KutupItem[] = []
    const files: KutupItem[] = []
    for (const folder of drive.index?.all ?? []) {
      if (!folder.key) continue
      const name = folderName(folder, myFiles)
      if (!name) continue
      const item: KutupItem = { type: 'folder', id: folder.id, name, kind: 'folder', folder, where: pathOf(drive.index, folder, myFiles) }
      byId.set(folder.id, item)
      folders.push(item)
    }
    const addFile = (folder: Folder, file: DriveFile, where: string) => {
      if (!file.name || byId.has(file.id)) return
      const item: KutupItem = { type: 'file', id: file.id, name: file.name, kind: file.kind, folder, file, where }
      byId.set(file.id, item)
      files.push(item)
    }
    for (const { folder, file } of drive.files) addFile(folder, file, pathOf(drive.index, folder, myFiles))
    for (const entry of shared.data ?? []) {
      if (entry.state === 'waiting') continue
      addFile(entry.container, entry.file, sharedWithMe)
    }
    return { byId, all: [...folders, ...files], ready: enabled && !drive.loading && !shared.isPending }
  }, [drive.index, drive.files, drive.loading, shared.data, shared.isPending, enabled, myFiles, sharedWithMe])
}
