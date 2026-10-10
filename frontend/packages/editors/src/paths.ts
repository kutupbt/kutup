import type { NavigateFunction } from 'react-router-dom'
import { isListName } from '@kutup/map/list'
import { appUrl } from '@kutup/session/apps'
import { getClientType } from '@kutup/session/client'
import type { Folder } from '@kutup/drive-core/model'
import { opensInOffice } from '@kutup/drive-core/editorKind'

// Each file has one address, whichever app it was opened from
// (docs/architecture.md, "File editor route"): what is edited opens in Office —
// notes and code, office documents, PDFs, whiteboards — a place list in
// Maps, and anything else (photos, videos, audio, other files) in Drive.

/** The app a file opens in. */
export type FileApp = 'drive' | 'office' | 'maps'

/** The apps that hold the file page: Drive and Office. */
export type FilePageApp = Exclude<FileApp, 'maps'>

export function appFor(name: string | null): FileApp {
  if (!name) return 'drive'
  if (isListName(name)) return 'maps'
  if (opensInOffice(name)) return 'office'
  return 'drive'
}

/** The app this page belongs to. */
export function currentApp(): FilePageApp {
  return getClientType() === 'web-office' ? 'office' : 'drive'
}

/** Where `from` came from, when it is one of the apps the back button knows. */
export function openedFrom(value: string | null): FilePageApp | null {
  return value === 'drive' || value === 'office' ? value : null
}

/** A folder's page in Drive. */
export function folderPath(folder: Pick<Folder, 'id' | 'source' | 'remoteShareId' | 'isRoot'>): string {
  if (folder.isRoot) return '/'
  // A file shared by itself has no folder to go back to.
  if (folder.source === 'file') return '/shared'
  if (folder.source === 'remote' && folder.remoteShareId) return `/remote/${folder.remoteShareId}`
  return `/folders/${folder.id}`
}

/** A file's page, in whichever of Drive and Office opens it: the same path in both. */
export function filePath(folder: Pick<Folder, 'id' | 'source'>, fileId: string): string {
  if (folder.source === 'file') return `/shared/file/${fileId}`
  return `/file/${folder.id}/${fileId}`
}

/**
 * Where a place list opens: in the Maps app (docs/plans/maps.md, step 4).
 * Opened from Drive, it is marked so that its back button returns to the
 * folder.
 */
export function mapsListUrl(folder: Pick<Folder, 'id' | 'source' | 'remoteShareId'>, fileId: string, fromDrive = true): string {
  const path = folder.source === 'file'
    ? `/shared/${fileId}`
    : folder.source === 'remote' && folder.remoteShareId
      ? `/remote/${folder.remoteShareId}/${fileId}`
      : `/lists/${folder.id}/${fileId}`
  return appUrl('maps', fromDrive ? `${path}?from=drive` : path)
}

/**
 * A file's address in the app that opens it, marked with the app it was
 * opened from (`from`) so that its back button returns there.
 */
export function fileUrl(folder: Pick<Folder, 'id' | 'source' | 'remoteShareId'>, file: { id: string; name: string | null }, from: FilePageApp): string {
  const app = appFor(file.name)
  if (app === 'maps') return mapsListUrl(folder, file.id, from === 'drive')
  return appUrl(app, `${filePath(folder, file.id)}?from=${from}`)
}

/** Open a file: on this page when this app opens it, otherwise in the app that does. */
export function openFile(navigate: NavigateFunction, folder: Pick<Folder, 'id' | 'source' | 'remoteShareId'>, file: { id: string; name: string | null }): void {
  const here = currentApp()
  if (appFor(file.name) === here) void navigate(filePath(folder, file.id))
  else window.location.assign(fileUrl(folder, file, here))
}

/**
 * A public link's folder page, in Drive. `hash` is the link's fragment
 * (`#key=…`): the key goes along, never through a server.
 */
export function publicFolderUrl(token: string, hash: string): string {
  return appUrl('drive', `/s/${encodeURIComponent(token)}${hash}`)
}

/** A document in a public link's folder, on Office; `hash` as above. */
export function publicDocumentUrl(token: string, fileId: string, hash: string): string {
  return appUrl('office', `/s/${encodeURIComponent(token)}/${encodeURIComponent(fileId)}${hash}`)
}
