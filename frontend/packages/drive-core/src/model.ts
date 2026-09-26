import type { FileKeyHistoryEntry } from '@kutup/session/api-types'
import type { FileKind } from './kinds'

/** The name the root collection is created with; it is found by this name. */
export const ROOT_NAME = 'My Files'

/**
 * One folder, whatever its origin. Every Drive page works with this shape so
 * none of them branch on where a folder came from — only on what it allows.
 */
export interface Folder {
  /**
   * `file`: not a folder the account can open, only the place a file shared
   * by itself lives (docs/plans/drive-file-sharing.md). It has no key, name
   * or listing; the file opens with its own key.
   */
  source: 'owned' | 'shared' | 'remote' | 'file'
  /** The collection id (for a remote share, the collection on the other server). */
  id: string
  /** Present for remote shares: the local id of the incoming share. */
  remoteShareId?: string
  /**
   * For a file shared by itself from another server (source `file`): the
   * local id of the accepted invite, through which its content is read.
   */
  remoteFileShareId?: string
  parentId: string | null
  /** Null when it could not be decrypted (a damaged or foreign record). */
  name: string | null
  key: Uint8Array | null
  keyEpoch: number
  /** Who owns it and whose authority signs its key history. */
  ownerUserId: string
  ownerAuthorityPublicKey: string
  /** The current epoch's statement hash: a new one means a new keyring. */
  epochStatementHash: string
  /** Needed to rename (the next revision is current + 1). */
  nameRevision: number
  color: string | null
  createdAt: string
  updatedAt: string
  /** "alice@example.org" for folders someone else owns. */
  ownerAccount: string | null
  canUpload: boolean
  canDelete: boolean
  /** Owner-only actions: rename, colour, share, public link, subfolders, delete. */
  canManage: boolean
  isRoot: boolean
}

export interface DriveFile {
  id: string
  collectionId: string
  uploaderUserId: string | null
  /** The folder epoch the file key is wrapped at; below the folder's, the file is re-keyed before it is written to or moved. */
  keyEpoch: number
  /** The generation of the file's current key (docs/plans/drive-move.md). */
  keyGeneration: number
  metadataRevision: number
  /** Null when it could not be decrypted. */
  name: string | null
  mimeType: string
  /** Plaintext bytes. */
  size: number
  /** The file key of `keyGeneration`. */
  fileKey: Uint8Array | null
  /** The key generation the upload was sealed under. */
  originalKeyGeneration: number
  /** The key generation of what a download serves. */
  contentKeyGeneration: number
  /** The file's older keys, each sealed under the next. */
  keyHistory: FileKeyHistoryEntry[]
  kind: FileKind
  createdAt: string
  updatedAt: string
  /** When each thumbnail was stored (the value versions its URL), and its key generation. */
  thumbnails: { sm?: string; lg?: string; smKeyGeneration?: number; lgKeyGeneration?: number }
  /** Drawn from something other than the latest content: redraw. */
  thumbnailStale: boolean
  /** The owner shared it with someone by itself. */
  shared: boolean
}

/** Where a folder's files come from and go to. */
export function folderLocation(folder: Pick<Folder, 'id' | 'source' | 'remoteShareId'>): { kind: 'local'; collectionId: string } | { kind: 'remote'; shareId: string } {
  return folder.source === 'remote' && folder.remoteShareId
    ? { kind: 'remote', shareId: folder.remoteShareId }
    : { kind: 'local', collectionId: folder.id }
}

/** Where one file's content (and a note's or place list's saved state) is read from. */
export type FileLocation =
  | { kind: 'local' }
  | { kind: 'remoteFolder'; shareId: string }
  | { kind: 'remoteFile'; shareId: string }

export function fileLocation(folder: Pick<Folder, 'source' | 'remoteShareId' | 'remoteFileShareId'>): FileLocation {
  if (folder.remoteFileShareId) return { kind: 'remoteFile', shareId: folder.remoteFileShareId }
  if (folder.source === 'remote' && folder.remoteShareId) return { kind: 'remoteFolder', shareId: folder.remoteShareId }
  return { kind: 'local' }
}

/** The file's current encrypted content, under the API base. */
export function contentPath(location: FileLocation, fileId: string): string {
  switch (location.kind) {
    case 'local':
      return `/files/${fileId}/download`
    case 'remoteFolder':
      return `/drive/federation/shares/${location.shareId}/files/${fileId}/content`
    case 'remoteFile':
      return `/drive/federation/file-shares/${location.shareId}/content`
  }
}

/**
 * For a file on another server: where its saved Yjs state (a note's or place
 * list's edits) is relayed from, as `{ keyGeneration, state }`. Local files
 * read their versions instead.
 */
export function remoteStatePath(location: FileLocation, fileId: string): string | null {
  switch (location.kind) {
    case 'local':
      return null
    case 'remoteFolder':
      return `/drive/federation/shares/${location.shareId}/files/${fileId}/state`
    case 'remoteFile':
      return `/drive/federation/file-shares/${location.shareId}/state`
  }
}
