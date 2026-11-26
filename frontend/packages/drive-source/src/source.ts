// The Drive screens' data, whatever stores it (docs/plans/drive-source.md).
//
// Kutup passes its end-to-end encrypted implementation (drive-core); another
// app can pass a plain one. The screens see only what is here: a folder's and
// a file's view, operations by id, and what the source can do. How a file is
// sealed, keyed, uploaded or listed stays inside the implementation.
//
// DRAFT for review: the shapes below are the proposal of PR 1; nothing uses
// them yet.

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
  /** Where it is: one's own, shared with one, on another server, or a single shared file's place. */
  origin: 'owned' | 'shared' | 'remote' | 'file'
}

/** A file as the screens show it. */
export interface FileView {
  id: string
  folderId: string
  name: string | null
  mimeType: string
  /** Bytes of the content. */
  size: number
  kind: string
  createdAt: string
  updatedAt: string
  /** The owner shared it by itself (not only through its folder). */
  shared: boolean
  /** A photo's or video's details, when known. */
  media: MediaView | null
  /** Who added it, when the source knows (an account id the people lookup names). */
  uploaderAccountId: string | null
}

export interface MediaView {
  takenAt?: number
  width?: number
  height?: number
  durationMs?: number
  latitude?: number
  longitude?: number
}

/** What a source can do; the screens hide what is missing. */
export interface Capabilities {
  /** Identity pins and key-change warnings (end-to-end encryption). */
  identityPins: boolean
  /** Sharing with accounts on other servers. */
  federation: boolean
  /** Folder colours. */
  folderColors: boolean
  /** Upload-only links (file requests). */
  uploadLinks: boolean
  /** Server-made thumbnails: the screens ask `preview` and draw nothing themselves. */
  serverThumbnails: boolean
}

export type Conflict = 'fail' | 'rename' | 'version'

/** An upload in progress; what the upload panel shows and controls. */
export interface UploadHandle {
  id: string
  name: string
  size: number
  /** 0..size */
  progress(): number
  pause(): void
  resume(): void
  cancel(): Promise<void>
  /** Resolves with the new or updated file. */
  done: Promise<FileView>
}

/** Uploads, including the ones that come back after a reload. */
export interface UploadEngine {
  upload(file: File, to: FolderView, opts: { relativePath?: string; onConflict: Conflict }): UploadHandle
  /** Uploads left unfinished by an earlier page (Kutup: pendingUploads; plain: tus). */
  pending(): Promise<UploadHandle[]>
}

export interface VersionView {
  id: string
  createdAt: string
  size: number
  label: string | null
  authorAccountId: string | null
}

export interface TrashedView {
  id: string
  name: string | null
  isFolder: boolean
  size: number
  trashedAt: string
  /** The folder it was in, if it is still there. */
  fromFolderId: string | null
}

/**
 * The data source of the Drive screens. Hooks are React Query hooks keyed by
 * the source; a source is created once per app and never replaced.
 */
export interface DriveSource {
  readonly capabilities: Capabilities

  // browsing
  useFolders(): { data: FolderView[] | undefined; isLoading: boolean; error: unknown }
  useFolderFiles(folder: FolderView | undefined): { data: FileView[] | undefined; isLoading: boolean; error: unknown }
  useTrash(): { data: TrashedView[] | undefined; isLoading: boolean; error: unknown }

  // changes (each invalidates what it changed)
  createFolder(parent: FolderView, name: string): Promise<FolderView>
  renameFolder(folder: FolderView, name: string): Promise<void>
  renameFile(file: FileView, name: string): Promise<void>
  moveFile(file: FileView, to: FolderView): Promise<void>
  copyFile(file: FileView, to: FolderView): Promise<FileView>
  trashFolder(folder: FolderView): Promise<void>
  trashFile(file: FileView): Promise<void>
  restore(entry: TrashedView): Promise<void>
  purge(entry: TrashedView): Promise<void>

  // content
  readonly uploads: UploadEngine
  /** The current content (or a version's) as a stream the browser can save or play. */
  download(file: FileView, version?: string): Promise<ReadableStream<Uint8Array>>
  /** A thumbnail's object URL, or null when there is none. */
  preview(file: FileView, size: 'sm' | 'lg'): Promise<string | null>

  // versions
  versions(file: FileView): Promise<VersionView[]>
  restoreVersion(file: FileView, version: string): Promise<void>
}
