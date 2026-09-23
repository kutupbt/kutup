import type { FileKind } from '../explorer/kinds'

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
  keyEpoch: number
  metadataRevision: number
  /** Null when it could not be decrypted. */
  name: string | null
  mimeType: string
  /** Plaintext bytes. */
  size: number
  fileKey: Uint8Array | null
  kind: FileKind
  createdAt: string
  updatedAt: string
}

/** Where a folder's files come from and go to. */
export function folderLocation(folder: Folder): { kind: 'local'; collectionId: string } | { kind: 'remote'; shareId: string } {
  return folder.source === 'remote' && folder.remoteShareId
    ? { kind: 'remote', shareId: folder.remoteShareId }
    : { kind: 'local', collectionId: folder.id }
}
