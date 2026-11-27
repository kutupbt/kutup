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
import type { ComponentType, ReactNode } from 'react'
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
  /** The owner's permanent id (Kutup: account id; home: the account server's subject). */
  ownerAccountId: string
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

/** A version of a file from its history. */
export interface VersionView {
  id: string
  createdAt: string
  /** Bytes of that version's content. */
  sizeBytes: number
  authorAccountId?: string | null
}

/** One entry of a file's history: an earlier version, or what it holds now. */
export interface HistoryEntryView extends VersionView {
  /** `file`: the whole file; `yjs`: a note's (or code file's, place list's) saved state. */
  kind: 'file' | 'yjs'
  label: string | null
  keepForever: boolean
  /** What the file holds now. */
  current: boolean
}

/** Why restoring a version did not happen (the screens say it in words). */
export type RestoreProblem = 'changed' | 'ownUpload' | 'othersUpload'

/** A file's history and what can be done with it; every change refreshes it. */
export interface VersionHistory {
  history: { data: HistoryEntryView[] | undefined; isPending: boolean; isError: boolean; error: unknown }
  /** Whether an earlier version can be made current here. */
  mayRestore: boolean
  mayDelete: (entry: HistoryEntryView, history: readonly HistoryEntryView[]) => boolean
  /** Makes it the newest version again; every other version stays. */
  restore: (entry: HistoryEntryView) => Promise<{ done: true } | { problem: RestoreProblem }>
  keep: (entry: HistoryEntryView, keepForever: boolean) => Promise<void>
  remove: (entry: HistoryEntryView) => Promise<void>
}

/** Someone as the details show them: a name, with their address as its tooltip. */
export interface PersonName {
  name: string
  address?: string
}

/** A person still being looked up, or not known. */
export type PersonLookup = PersonName | 'pending' | 'unknown'

/** What a file's details show beyond the file itself. */
export interface FileDetailsInfo {
  /** Who uploaded it first; null: no row. */
  createdBy: PersonLookup | null
  /** Who saved what it holds now, when not its creator; null: no row. */
  lastUploadedBy: PersonLookup | null
  /** What the current content takes in storage; null when not known. */
  storedSize: number | null
  /** How many entries its history has; null when it has none here. */
  versions: number | null
  /** The content's SHA-256 (hex), while it still says what the content is. */
  sha256: string | null
}

/** What the owner shares an item with, counted. */
export interface SharingSummary {
  /** People and accounts on other servers. */
  people: number
  links: number
  /** The file's folder is shared too. */
  folderShared: boolean
}

/** A player's source for a file's video or audio. */
export type Playback =
  /** A URL to play (streamed, or a Blob's URL); `close` ends it. */
  | { kind: 'ready'; src: string; streamed: boolean; close: () => void }
  /** Too large to play here. */
  | { kind: 'tooLarge' }
  /** Too many playing at once in this tab. */
  | { kind: 'busy' }

/** What a stream that failed before it played is replaced with. */
export type PlaybackFallback = Playback | { kind: 'failed' }

/** The props of a dialog the source supplies: what it is for, and whether it is open. */
export interface SlotProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

/**
 * Making a public link. A link is made on the server, so it is made on the
 * person's action (`create`, from the menu item), never while rendering or in an
 * effect: a dialog that made its link when it opened would make one more each
 * time its props changed. `dialog` shows the link made, once.
 */
export interface PublicLinkAction {
  create: (target: ItemRef) => void
  dialog: ReactNode
}

/** Something the person shares: a folder, or a file shared by itself, with counts. */
export interface SharedByMeView {
  folder: FolderView
  file?: FileView
  people: number
  /** Capability `federation`: accounts on other servers. */
  otherServers?: number
  links: number
}

/** A file shared with the person by itself (not through a folder). */
export interface SharedWithMeFileView {
  file: FileView
  /** Where it lives, as far as the person can tell (no folder of theirs). */
  container: FolderView
  canEdit: boolean
  /** An editor the owner lets share it on. */
  canShare: boolean
  /**
   * `ready`; `gone`: the owner deleted it; `waiting` and `editsWait`: access
   * is on its way (Kutup: keys not yet received). A plain source is ready or gone.
   */
  state: 'ready' | 'editsWait' | 'waiting' | 'gone'
  /** Who shared it, and whose it is (they differ when an editor passed it on). */
  sharerAccount: string
  ownerAccount: string
}

/** What a source can do; the screens hide what is missing. */
export interface Capabilities {
  /** Accepting invites from other servers (the AcceptInviteDialog slot). */
  invites: boolean
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
  /** Whether a file can be opened, read and downloaded (Kutup: its key is at hand). */
  isFileOpen: (file: FileView) => boolean
  /** Whether files in a folder offer their version history. */
  offersHistory: (folder: FolderView) => boolean
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
  /** A file's current content, for a viewer in the page. */
  read: (folder: FolderView, file: FileView, signal?: AbortSignal) => Promise<Blob>
  /** A version's content, for a viewer in the page. */
  readVersion: (file: FileView, version: VersionView, signal?: AbortSignal) => Promise<Blob>
  /**
   * A file's video or audio for a player, streamed where it can be. A stream
   * that fails before it plays is replaced, and `onFallback` hears of it.
   */
  openPlayback: (
    folder: FolderView,
    file: FileView,
    signal?: AbortSignal,
    onProgress?: (read: number) => void,
    onFallback?: (next: PlaybackFallback) => void,
  ) => Promise<Playback>

  /** Saves one file to the computer by the source's own rules (Kutup: large files streamed to disk). */
  downloadFile: (folder: FolderView, file: FileView) => Promise<void>
  useFileDetails: (folder: FolderView, file: FileView) => FileDetailsInfo
  /** Who made a folder (one's own: oneself). */
  useFolderCreator: (folder: FolderView) => PersonLookup
  /** What the owner shares a folder (or a file in it) with; undefined while loading, null when not shared. */
  useSharingSummary: (folder: FolderView, file?: FileView) => SharingSummary | null | undefined
  /**
   * Everything to search, by name, in the browser: the folder tree and every
   * file the person can read (Kutup decrypts every listing; its own index).
   * A source that searches on its server can later offer that instead.
   */
  useSearchIndex: (enabled: boolean) => { index: FolderTree | undefined; files: { folder: FolderView; file: FileView }[]; loading: boolean }
  /** Files shared with the person by themselves (shared folders are in `useFolders`' `sharedWithMe`). */
  useSharedFiles: () => UseQueryResult<SharedWithMeFileView[]>
  /** Whether the person can leave a folder or a file shared with them (Kutup: shares from other servers). */
  mayLeaveFolder: (folder: FolderView) => boolean
  mayLeaveFile: (shared: SharedWithMeFileView) => boolean
  useLeaveFolder: () => UseMutationResult<void, Error, FolderView>
  useLeaveFile: () => UseMutationResult<void, Error, SharedWithMeFileView>
  /** Someone's name as the person knows them (by their address). */
  usePersonName: (account: string) => string
  /** "From X · owned by Y" for something shared with the person (Kutup adds its identity warnings). */
  SharedFrom: ComponentType<{ shared: SharedWithMeFileView } | { folder: FolderView }>

  /** What the person shares, with counts. */
  useSharedByMe: () => { items: SharedByMeView[]; loading: boolean; error: unknown }
  /** Whether the owner shares an item (for the search filter); undefined while loading. */
  useSharedLookup: () => ((folder: FolderView, file?: FileView) => boolean) | undefined

  /** Whether the person may share an item with people. */
  mayShare: (item: ItemRef) => boolean
  /** Whether the person may make a public link to an item. */
  mayLink: (item: ItemRef) => boolean
  /**
   * The sharing dialogs, supplied by the source (Kutup's keep identity pins, the
   * key-rotation review and federation inside them; another source supplies
   * simpler ones). The screens pass only the item and whether it is open.
   */
  ShareDialog: ComponentType<SlotProps & { target: ItemRef | null }>
  /** A public link: made by `create` on the person's action, shown by `dialog`. */
  usePublicLink: () => PublicLinkAction
  /** Capability `invites`; null without. */
  AcceptInviteDialog: ComponentType<SlotProps> | null

  /** Shown above an item's details (Kutup: the check of the content's signature); null for none. */
  DetailsBanner: ComponentType<{ folder: FolderView; file: FileView }> | null

  useVersionHistory: (folder: FolderView, file: FileView) => VersionHistory
  /** Who saved a version, as a name to show; null when not known. */
  useAuthorName: (entry: HistoryEntryView) => string | null
  /** How long earlier versions are kept, where the person can change it (null: nothing to show). */
  useVersionRetention: () => { days: number } | null

  /** Saves a version from a file's history under the file's name. */
  downloadVersion: (file: FileView, version: VersionView) => Promise<void>
  /** A folder (its own files) as a ZIP; 'empty' when there was nothing to put in. */
  downloadFolderZip: (folder: FolderView, onProgress: (done: number, total: number) => void) => Promise<'empty' | 'done'>
  /** Several items as one ZIP named `archive`. */
  downloadSelectionZip: (items: ItemRef[], archive: string, onProgress: (done: number, total: number) => void) => Promise<'empty' | 'done'>
  /** What a failed download means for the person: too large to zip here, too large for this browser, or other. */
  downloadFailure: (error: unknown) => 'zipTooLarge' | 'fileTooLarge' | 'other'

  /**
   * A file's thumbnail as a URL for an <img>, or null (the kind's icon shows).
   * The screens never draw one: the source makes them (Kutup in the browser,
   * after an upload, and redraws a missing or stale one when its grid picture,
   * `sm`, is on screen).
   */
  thumbnail: (folder: FolderView, file: FileView, size: 'sm' | 'lg') => Promise<string | null>
  /** Changes whenever the file's thumbnail does (when to ask again). */
  thumbnailStamp: (file: FileView) => string
  /** Why an item cannot be moved into `dest` by this source's rules, or null when it can. */
  moveRefusal: (tree: FolderTree, item: ItemRef, dest: FolderView) => MoveRefusal | null
}
