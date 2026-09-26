import type { NavigateFunction } from 'react-router-dom'
import { isListName } from '@kutup/map/list'
import { appUrl } from '@kutup/session/apps'
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

/** Where a place list opens: in the Maps app (docs/plans/maps.md, step 4). */
export function mapsListUrl(folder: Pick<Folder, 'id' | 'source' | 'remoteShareId'>, fileId: string): string {
  if (folder.source === 'file') return appUrl('maps', `/shared/${fileId}`)
  if (folder.source === 'remote' && folder.remoteShareId) return appUrl('maps', `/remote/${folder.remoteShareId}/${fileId}`)
  return appUrl('maps', `/lists/${folder.id}/${fileId}`)
}

/** Open a file: here in its editor or viewer, or a place list in Maps. */
export function openFile(navigate: NavigateFunction, folder: Pick<Folder, 'id' | 'source' | 'remoteShareId'>, file: { id: string; name: string | null }): void {
  if (isListName(file.name)) window.location.assign(mapsListUrl(folder, file.id))
  else void navigate(filePath(folder, file.id))
}
