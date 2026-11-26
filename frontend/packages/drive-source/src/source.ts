// The Drive screens' data, whatever stores it (docs/plans/drive-source.md).
//
// Kutup passes its end-to-end encrypted implementation (drive-core); another
// app can pass a plain one. The screens see only what is here: a folder's and
// a file's view, operations on views, and what the source can do. How a file
// is sealed, keyed, uploaded, listed or searched stays inside the
// implementation.
//
// DRAFT (PR 1 of 4, revised after review): nothing uses it yet.

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
  origin: 'owned' | 'shared' | 'remote' | 'file'
}

/**
 * A file as the screens show it. Its kind is not here: both apps derive it
 * the same way from name and type (drive-core's `kinds` and `editorKind`), so
 * "open in Office" is decided alike everywhere.
 */
export interface FileView {
  id: string
  folderId: string
  name: string | null
  mimeType: string
  /** Bytes of the content. */
  size: number
  createdAt: string
  updatedAt: string
  /**
   * The current content's revision: what a version save or an editor's save
   * names as the base it started from, and what the details panel shows.
   * Null when the source cannot say.
   */
  revisionId: string | null
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

/**
 * What a source can do; the screens hide what is missing. Each of Kutup's
 * sharing features has its own flag, so another source can simply say no.
 */
export interface Capabilities {
  /** Identity pins and key-change warnings (end-to-end encryption). */
  identityPins: boolean
  /** Sharing with accounts on other servers. */
  federation: boolean
  /** Leaving a share another server made with one (folder and single file). */
  leaveRemoteShares: boolean
  /** Accepting invites (parseInvite / acceptInvite). */
  invites: boolean
  /** Roles beyond read and write. */
  roles: boolean
  /** "Editors can share". */
  editorsCanShare: boolean
  /** Links to single files, besides links to folders. */
  fileLinks: boolean
  linkPasswords: boolean
  /** Upload-only links (file requests). */
  uploadLinks: boolean
  folderColors: boolean
  /**
   * The source makes thumbnails itself (a server, or Kutup's upload engine in
   * the browser): the screens only ask `preview` and never draw one.
   */
  serverThumbnails: boolean
}

/** What happens when a name is taken: fail, take a free name, or (files) a new version. */
export type Conflict = 'fail' | 'rename' | 'version'

export interface UploadProgress {
  /** 0..size */
  sent: number
  state: 'queued' | 'running' | 'paused' | 'done' | 'failed' | 'cancelled'
  error?: unknown
}

/** An upload in progress; what the upload panel shows and controls. */
export interface UploadHandle {
  id: string
  name: string
  size: number
  progress(): UploadProgress
  /** Called on every change of progress or state; returns the unsubscribe. */
  subscribe(listener: (progress: UploadProgress) => void): () => void
  pause(): void
  resume(): void
  cancel(): Promise<void>
  /** Resolves with the new or updated file. */
  done: Promise<FileView>
}

/** Uploads, including the ones that come back after a reload. */
export interface UploadEngine {
  upload(file: File, to: FolderView, opts: { relativePath?: string; onConflict: Conflict }): UploadHandle
  /**
   * A new version of an existing file from the revision the caller started
   * from (refused if the file changed meanwhile).
   */
  replaceContent(file: FileView, content: File | Blob, baseRevisionId: string | null): UploadHandle
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

export interface SearchFilters {
  folderId?: string
  kinds?: string[]
  modifiedAfter?: string
  modifiedBefore?: string
}

export type SearchHit = { file: FileView; folder: FolderView } | { folder: FolderView; file?: undefined }

export interface Principal {
  kind: 'user' | 'group'
  /** An account (Kutup) or a subject (home), or a group's name. */
  id: string
  name: string
}

export interface ShareView {
  id: string
  principal: Principal
  /** read, write, or a source's own roles (capability `roles`). */
  role: string
}

export interface LinkView {
  id: string
  /** Shown once, when made, where the source cannot show it again. */
  url: string | null
  kind: 'download' | 'upload'
  hasPassword: boolean
  expiresAt: string | null
  downloads: number | null
  maxDownloads: number | null
}

export interface LinkOptions {
  kind: 'download' | 'upload'
  password?: string
  expiresAt?: string | null
  maxDownloads?: number | null
}

/** Sharing: a small common core; Kutup's extras are optional and flagged. */
export interface SharingSource {
  shares(item: FolderView | FileView): Promise<ShareView[]>
  share(item: FolderView | FileView, principal: Principal, role: string): Promise<ShareView>
  unshare(share: ShareView): Promise<void>
  /** People and groups to share with. */
  people(query: string): Promise<Principal[]>
  links(item: FolderView | FileView): Promise<LinkView[]>
  createLink(item: FolderView | FileView, opts: LinkOptions): Promise<LinkView>
  updateLink(link: LinkView, change: Partial<LinkOptions>): Promise<LinkView>
  revokeLink(link: LinkView): Promise<void>
  /** Capability `editorsCanShare`. */
  setEditorsCanShare?(folder: FolderView, allowed: boolean): Promise<void>
  /** Capability `leaveRemoteShares`. */
  leave?(item: FolderView | FileView): Promise<void>
  /** Capability `invites`: what an invite link or code is, or null if it is none. */
  parseInvite?(value: string): { kind: 'folder' | 'file' | 'album'; server: string } | null
  acceptInvite?(value: string): Promise<FolderView>
}

export interface Query<T> {
  data: T | undefined
  isLoading: boolean
  error: unknown
}

/**
 * The data source of the Drive screens. Hooks are React Query hooks; Kutup's
 * implementation keeps drive-core's query keys exactly, because the editors,
 * Calendar's attachments and the upload commit invalidate Drive's lists by
 * those keys. A source is created once per app and never replaced.
 */
export interface DriveSource {
  readonly capabilities: Capabilities

  // lists
  useFolders(): Query<FolderView[]>
  useFolderFiles(folder: FolderView | undefined): Query<FileView[]>
  useTrash(): Query<TrashedView[]>
  useSharedWithMe(): Query<(FolderView | FileView)[]>
  useSharedByMe(): Query<(FolderView | FileView)[]>
  /** Kutup searches in the browser over its decrypted index; a server source searches on the server. */
  search(query: string, filters: SearchFilters): Promise<SearchHit[]>
  /** The names in a folder, for the conflict dialog. */
  namesIn(folder: FolderView): Promise<Set<string>>

  // changes (each invalidates what it changed)
  createFolder(parent: FolderView, name: string): Promise<FolderView>
  renameFolder(folder: FolderView, name: string): Promise<void>
  renameFile(file: FileView, name: string): Promise<void>
  setFolderColor(folder: FolderView, color: string | null): Promise<void>
  moveFile(file: FileView, to: FolderView, onConflict: Conflict): Promise<void>
  copyFile(file: FileView, to: FolderView, onConflict: Conflict): Promise<FileView>
  /** Whole folders: Kutup's recursive move and copy (apps/drive features/drive) move into its implementation. */
  moveFolder(folder: FolderView, to: FolderView, onConflict: Conflict): Promise<void>
  copyFolder(folder: FolderView, to: FolderView, onConflict: Conflict): Promise<FolderView>
  trashFolder(folder: FolderView): Promise<void>
  trashFile(file: FileView): Promise<void>
  restore(entry: TrashedView): Promise<void>
  purge(entry: TrashedView): Promise<void>
  emptyTrash(): Promise<void>

  // content
  readonly uploads: UploadEngine
  /**
   * Saves the file (or a version) to the computer, by the source's own rules
   * (Kutup: large files through the File System Access API, BlobDownloadTooLarge).
   */
  download(file: FileView, opts?: { version?: string; saveAs?: boolean }): Promise<void>
  /** A folder and everything in it as a ZIP. */
  downloadFolderZip(folder: FolderView): Promise<void>
  /** The content (or a version's) for a viewer in the page. */
  read(file: FileView, opts?: { version?: string }): Promise<Blob>
  /** A thumbnail's object URL, or null when there is none. */
  preview(file: FileView, size: 'sm' | 'lg'): Promise<string | null>

  // versions
  versions(file: FileView): Promise<VersionView[]>
  restoreVersion(file: FileView, version: string): Promise<void>

  readonly sharing: SharingSource
}
