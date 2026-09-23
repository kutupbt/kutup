import type { Folder } from './model'

export function folderPath(folder: Pick<Folder, 'id' | 'source' | 'remoteShareId' | 'isRoot'>): string {
  if (folder.isRoot) return '/'
  if (folder.source === 'remote' && folder.remoteShareId) return `/remote/${folder.remoteShareId}`
  return `/folders/${folder.id}`
}

/** Where a file opens: its editor or viewer page. */
export function filePath(folder: Pick<Folder, 'id'>, fileId: string): string {
  return `/file/${folder.id}/${fileId}`
}
