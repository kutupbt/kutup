// The Drive screens' data, whatever stores it (docs/plans/drive-source.md).
//
// Kutup passes its end-to-end encrypted implementation; another app can pass a
// plain one. The screens see only what is here. The interface grows with the
// conversion, one step at a time: it holds what is implemented and used, and
// the plan holds the whole target (as reviewed on #458).
//
// The views use Kutup's own field names, so Kutup's objects pass through
// unchanged (no copies, the same identities for the screens' memoisation), and
// the hooks are drive-core's, so every query key stays as it is.

import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query'
import type { FileKind, ItemKind } from './kinds'
import type { AskRestoreName } from './restore'

/** A folder as the screens show it. */
export interface FolderView {
  id: string
  parentId: string | null
  /** Null when it cannot be shown (Kutup: it could not be decrypted). */
  name: string | null
  color: string | null
  createdAt: string
  updatedAt: string
  /** "alice@example.org" for folders someone else owns; null for one's own. */
  ownerAccount: string | null
  canUpload: boolean
  canDelete: boolean
  /** Rename, colour, share, links, subfolders, delete. */
  canManage: boolean
  isRoot: boolean
  /** One's own, shared with one, on another server, or a single shared file's place. */
  source: 'owned' | 'shared' | 'remote' | 'file'
  /** Federation: the share a folder on another server is reached through (its route, `/remote/:id`). */
  remoteShareId?: string
  /** Federation: the share a single file from another server is reached through. */
  remoteFileShareId?: string
}

/** Every folder the person can see, and how they hang together. */
export interface FolderTree<F extends FolderView = FolderView> {
  all: F[]
  byId: Map<string, F>
  root: F
  /** Own top-level folders other than the root. */
  looseTopLevel: F[]
  sharedWithMe: F[]
  childrenOf: (id: string) => F[]
}

/** A photo's or video's details (Kutup's MediaMetadataV1 names). */
export interface MediaView {
  /** UTC milliseconds. */
  takenAt?: number
  lat?: number
  lon?: number
  width?: number
  height?: number
  durationMs?: number
  camera?: string
  /** A live photo's video: the file id of its still. */
  liveOf?: string
}

/** A file as the screens show it. */
export interface FileView {
  id: string
  /** The folder it is in. */
  collectionId: string
  name: string | null
  mimeType: string
  /** Bytes of the content. */
  size: number
  /** Always `fileKind(name, mimeType)` from `./kinds`: decided alike whatever the source. */
  kind: FileKind
  createdAt: string
  updatedAt: string
  /**
   * The current content's revision: the base a version save or an editor's
   * save names, and what the details panel shows. Null when not known.
   */
  content: { revisionId: string } | null
  /** The owner shared it by itself (not only through its folder). */
  shared: boolean
  media: MediaView | null
  uploaderAccountId: string | null
}

/** An entry of the trash: a folder (with everything that was in it) or a file. */
export interface TrashedView {
  type: 'folder' | 'file'
  id: string
  name: string | null
  kind: ItemKind
  size: number | null
  deletedAt: string
  /** Folders: how many files went to the trash with it. */
  files?: number
}

/** A file of a dropped or chosen folder, with the folders it is in (not its own name). */
export interface FolderEntry {
  file: File
  relativePath: string[]
}

/**
 * Uploads as the screens start them; the source runs them (Kutup: sealed and
 * resumable, with its thumbnails drawn after the upload) and reports through
 * the shared upload panel.
 */
export interface UploadActions {
  uploadFiles: (folder: FolderView, files: File[]) => void
  uploadDirectory: (folder: FolderView, entries: FolderEntry[], name: string) => void
  /** Refreshes a folder's listing. */
  refreshFolder: (folder: FolderView) => Promise<void>
  /** After uploads: refresh what they changed (lists, storage used). */
  settled: () => void
  /** One new file (a new document from a template): its id, or null if none was made. */
  createFile: (folder: FolderView, file: File) => Promise<{ fileId: string } | null>
}

/** A folder, or a file in its folder: what is copied or moved. */
export type ItemRef = { folder: FolderView; file?: undefined } | { folder: FolderView; file: FileView }

/** Why an item cannot be moved into a folder (the screens say it in words). */
export type MoveRefusal = 'locked' | 'readOnly' | 'otherOwner' | 'remote' | 'notOwner' | 'intoItself' | 'alreadyThere'

/** What a source can do; the screens hide what is missing. */
export interface Capabilities {
  /** Folder colours. */
  folderColors: boolean
}

/**
 * The data source of the Drive screens. A source is one object for the whole
 * app, never replaced; its hooks follow the rules of hooks like any other.
 */
export interface DriveSource {
  readonly capabilities: Capabilities

  /** Whether a folder can be opened and listed (Kutup: its key is at hand). */
  isOpen: (folder: FolderView) => boolean
  /** The names of the files in a folder (for new names that are free). */
  namesIn: (folder: FolderView) => Promise<string[]>

  useFolders: () => UseQueryResult<FolderTree>
  useFolderFiles: (folder: FolderView | undefined) => UseQueryResult<FileView[]>
  useTrash: () => UseQueryResult<TrashedView[]>

  useCreateFolder: () => UseMutationResult<string, Error, { parent: FolderView; name: string }>
  useRenameFolder: () => UseMutationResult<void, Error, { folder: FolderView; name: string }>
  useRenameFile: () => UseMutationResult<void, Error, { folder: FolderView; file: FileView; name: string }>
  useSetFolderColor: () => UseMutationResult<void, Error, { folder: FolderView; color: string | null }>
  useTrashFolder: () => UseMutationResult<void, Error, FolderView>
  useTrashFile: () => UseMutationResult<void, Error, { folder: FolderView; file: FileView }>
  /** Restores an entry (or an id, for an undo); `ask` offers a free name when its own is taken. */
  useRestore: (ask?: AskRestoreName) => UseMutationResult<void, Error, TrashedView | string>
  /** Deletes a trash entry for good, by id. */
  usePurge: () => UseMutationResult<void, Error, string>
  useEmptyTrash: () => UseMutationResult<void, Error, void>

  useUploadActions: () => UploadActions

  /** Copies into `dest` (each item an entry in the upload panel; taken names get "(1)"…). */
  useCopy: () => (tree: FolderTree, items: ItemRef[], dest: FolderView) => Promise<void>
  /** Moves into `dest`, then says what happened with an undo; taken names stay where they are. */
  useMove: () => (tree: FolderTree, items: ItemRef[], dest: FolderView) => Promise<void>
  /** Whether an item can be moved at all by this source's rules (where to is `moveRefusal`'s). */
  mayMove: (item: ItemRef) => boolean
  /** Why an item cannot be moved into `dest` by this source's rules, or null when it can. */
  moveRefusal: (tree: FolderTree, item: ItemRef, dest: FolderView) => MoveRefusal | null
}
