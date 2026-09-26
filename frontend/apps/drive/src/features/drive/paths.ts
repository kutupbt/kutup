import type { Folder } from '@kutup/drive-core/model'

export function folderPath(folder: Pick<Folder, 'id' | 'source' | 'remoteShareId' | 'isRoot'>): string {
  if (folder.isRoot) return '/'
  // A file shared by itself has no folder to go back to.
  if (folder.source === 'file') return '/shared'
  if (folder.source === 'remote' && folder.remoteShareId) return `/remote/${folder.remoteShareId}`
  return `/folders/${folder.id}`
}

/** Where a file opens: its editor or viewer page. */
export function filePath(folder: Pick<Folder, 'id' | 'source'>, fileId: string): string {
  if (folder.source === 'file') return `/shared/file/${fileId}`
  return `/file/${folder.id}/${fileId}`
}
