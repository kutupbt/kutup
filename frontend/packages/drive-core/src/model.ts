import type { FileKeyHistoryEntry } from '@kutup/session/api-types'
import type { FileKind } from './kinds'

/** The name the root collection is created with; it is found by this name. */
export const ROOT_NAME = 'My Files'

/**
 * One folder, whatever its origin. Every Drive page works with this shape so
 * none of them branch on where a folder came from — only on what it allows.
 */
export interface Folder {
  source: 'owned' | 'shared' | 'remote'
  /** The collection id (for a remote share, the collection on the other server). */
  id: string
  /** Present for remote shares: the local id of the incoming share. */
  remoteShareId?: string
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
}

/** Where a folder's files come from and go to. */
export function folderLocation(folder: Pick<Folder, 'id' | 'source' | 'remoteShareId'>): { kind: 'local'; collectionId: string } | { kind: 'remote'; shareId: string } {
  return folder.source === 'remote' && folder.remoteShareId
    ? { kind: 'remote', shareId: folder.remoteShareId }
    : { kind: 'local', collectionId: folder.id }
}
