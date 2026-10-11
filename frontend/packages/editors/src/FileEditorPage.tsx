import { useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, BookmarkPlus, Check, Download, Eye, History, Save, UserPlus, WifiOff, X } from 'lucide-react'
import { Suspense, useCallback, useEffect, useRef, useState, useSyncExternalStore, type MutableRefObject, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { decryptFileBlobV1 } from '@kutup/crypto/fileBlob'
import { fileKind } from '@kutup/drive-core/kinds'
import { kindTileSvg } from '@kutup/drive-ui/kindTile'
import { appUrl } from '@kutup/session/apps'
import { useAccountUiPreferences } from '@kutup/session/uiPreferences'
import { QuotaExceededError } from '@kutup/session/errors'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'
import { KutupLogo } from '@kutup/ui/components/brand'
import { Button } from '@kutup/ui/components/button'
import { LoadingPanel } from '@kutup/ui/components/states'
import { ThemeToggle } from '@kutup/ui/components/theme-toggle'
import { formatBytes } from '@kutup/ui/lib/format'
import { NameDialog } from '@kutup/drive-ui/NameDialog'
import { downloadFile, FsaRequiredError } from './files/downloads'
import { filesKey, useFolderFiles } from '@kutup/drive-core/files'
import { fileKeyAt, sealedAt } from '@kutup/drive-core/keyring'
import { rekeyFile } from '@kutup/drive-core/rekey'
import { shareRole, useSharedFiles, type ShareRole } from '@kutup/drive-core/fileShares'
import { useFolders } from '@kutup/drive-core/folders'
import { useRenameFile } from '@kutup/drive-core/mutations'
import { personOf, usePeople } from '@kutup/drive-core/people'
import { collabBase, contentPath, fileLocation, type DriveFile, type FileLocation, type Folder } from '@kutup/drive-core/model'
import { appFor, currentApp, filePath, folderPath, mapsListUrl, openedFrom } from './paths'
import { contentAt, currentContent } from './content'
import CursorColorPicker from './CursorColorPicker'
import { OfficeEditor, TextCollabEditor, WhiteboardEditor } from './dispatch'
import { editorKindFor, extensionOf, type EditorKind } from '@kutup/drive-core/editorKind'
import type { OfficeEditorHandle, SessionBase } from './office/OfficeEditor'
import { EditorNotice } from './office/EditorNotice'
import { listVersions, patchVersion } from '@kutup/collab/api'
import { collabSocketFailures, resetCollabConnectivity, subscribeCollabConnectivity, unsentCollabFrames } from '@kutup/collab/connectivity'
import { loadVersionBytes, saveSnapshot, type LogPosition, type SnapshotTarget } from './snapshots'
import { renderPdfFirstPageV1 } from '@kutup/files/mediaPreview'
import { THUMBNAIL_MAX_SIDE } from '@kutup/crypto/thumbnail'
import { exportScene, thumbnailsOfDrawing, thumbnailsOfPicture } from './thumbnails/make'
import { enqueueThumbnail } from '@kutup/drive-core/thumbnailQueue'
import { storeThumbnails } from '@kutup/drive-core/thumbnails'
import RestoreConfirmDialog, { type RestoreChoice } from './versions/RestoreConfirmDialog'
import { FileShareDialog } from '@kutup/drive-ui/FileShareDialog'
import VersionHistoryPanel from './versions/VersionHistoryPanel'
import { chooseViewer } from './viewers/dispatch'
import { useCursorColor } from './useCursorColor'
import type { WhiteboardEditorHandle } from './whiteboard/WhiteboardEditor'

/**
 * Decrypted content lives entirely in tab memory, so a 2 GB video would take
 * the tab down. Anything larger is downloaded instead of opened.
 */
const MAX_OPEN_BYTES = 100 * 1024 * 1024

type Opened =
  | { kind: 'text'; initialText: string }
  /** `base`: the version the bytes came from and its log position (the office
   *  session's base); `resetBase`: claim it anew (after a restore). */
  | { kind: 'office' | 'whiteboard'; bytes: Uint8Array; base?: SessionBase; resetBase?: boolean }
  | { kind: 'viewer'; blobUrl: string; mimeType: string }
  /** Nothing in the browser opens it: offer the download. */
  | { kind: 'none' }

type Failure = 'notFound' | 'undecryptable' | 'tooLarge' | 'loadFailed' | 'waitingForOwner'

interface Keys {
  /** Where new saves and frames go: the file's current key and generation. */
  target: SnapshotTarget
  /** The file key of any generation: older log frames, versions and assets. */
  fileKeyAt: (generation: number) => Promise<Uint8Array>
}

/**
 * `/file/:cid/:fid`: one file, full screen. Notes and code open in the
 * collaborative text editor, office documents in OnlyOffice, whiteboards in
 * Excalidraw; images, PDFs and media in a viewer; anything else offers its
 * download. Keyed by the file, so moving to another file starts afresh.
 *
 * `/shared/file/:fid` (`shared`): a file someone shared by itself
 * (docs/plans/drive-file-sharing.md). It opens with its own key; there is no
 * folder behind it.
 */
/** Refused connection attempts in a row before asking whether the network is why. */
const LIVE_BLOCKED_AFTER = 3

/**
 * Whether this network blocks the live editing socket: several attempts in
 * a row never opened, yet the server answers an ordinary request. An editor
 * whose changes cannot leave the page must not look as if it were saving, so
 * the file is shown as it was last saved, read-only, until a socket opens.
 */
type LiveEditing = 'live' | 'blocked' | 'blockedWithEdits'

function useLiveEditingBlocked(): LiveEditing {
  const failures = useSyncExternalStore(subscribeCollabConnectivity, collabSocketFailures)
  const [state, setState] = useState<LiveEditing>('live')
  useEffect(() => {
    if (failures === 0) {
      setState('live')
      return
    }
    if (failures < LIVE_BLOCKED_AFTER || state !== 'live') return
    let alive = true
    // The server not answering either is an outage, not a blocked socket.
    api
      .get('/auth/settings')
      // Edits still waiting to be sent stay where they are: rebuilding the
      // editor read-only would throw them away. They go out if the socket
      // opens after all.
      .then(() => alive && setState(unsentCollabFrames() > 0 ? 'blockedWithEdits' : 'blocked'))
      .catch(() => undefined)
    return () => {
      alive = false
    }
  }, [failures, state])
  return state
}

export function FileEditorPage({ shared = false }: { shared?: boolean }) {
  const { cid = '', fid = '' } = useParams()
  // Outside Drive's shell, with its own theme switch.
  useAccountUiPreferences()
  return <OpenFile key={`${shared ? 'shared' : cid}/${fid}`} cid={shared ? null : cid} fid={fid} />
}

function OpenFile({ cid, fid }: { cid: string | null; fid: string }) {
  // Declared before the hook below, so it runs first for a new file.
  useEffect(() => resetCollabConnectivity(), [fid])
  const live = useLiveEditingBlocked()
  // Read-only only when nothing typed here is still waiting to be sent.
  const liveBlocked = live === 'blocked'
  const { t } = useTranslation()
  const session = useRequiredSession()
  const folders = useFolders()
  const inFolder = folders.data?.byId.get(cid ?? '')
  const folderFiles = useFolderFiles(inFolder)
  const sharedFiles = useSharedFiles({ enabled: cid === null })
  const sharedFile = cid === null ? sharedFiles.data?.find((s) => s.file.id === fid) : undefined
  const folder = cid === null ? sharedFile?.container : inFolder
  const file = cid === null ? sharedFile?.file : folderFiles.data?.find((f) => f.id === fid)
  // Either the folder's listing or, for a file shared by itself, the list of those.
  const files = cid === null ? sharedFiles : folderFiles

  // The folder and file as they were when the file opened. Their keys are
  // what the editors hold: a rename refetches the list, which decrypts fresh
  // key copies, and handing those over would tear the editors' sessions down
  // for nothing. Names and permissions are read live below.
  const queryClient = useQueryClient()
  const [picked, setPicked] = useState<{ folder: Folder; file: DriveFile } | null>(null)
  const [opened, setOpened] = useState<Opened | null>(null)
  const [keys, setKeys] = useState<Keys | null>(null)
  const [failure, setFailure] = useState<Failure | null>(null)
  // Bumped to remount a whole-file editor on restored content.
  const [generation, setGeneration] = useState(0)
  // Bumped to reopen the file from its latest version (another tab saved
  // past the point this one opened at).
  const [reopen, setReopen] = useState(0)
  // A live office session started from this version: open it, not the latest.
  const [openAt, setOpenAt] = useState<SessionBase | null>(null)

  const listsLoaded = cid === null ? files.isSuccess : folders.isSuccess && (!folder?.key || files.isSuccess)
  const refetching = folders.isFetching || files.isFetching
  useEffect(() => {
    if (picked || !listsLoaded) return
    if (sharedFile?.state === 'waiting') setFailure('waitingForOwner')
    // A file has one address: one opened in the other app goes there (a
    // link from before, or one typed in), and a place list to Maps.
    else if (folder && file && appFor(file.name) === 'maps') window.location.replace(mapsListUrl(folder, file.id))
    else if (folder && file && appFor(file.name) !== currentApp()) {
      const app = appFor(file.name) as 'drive' | 'office'
      window.location.replace(appUrl(app, `${filePath(folder, file.id)}${window.location.search}`))
    }
    else if (folder && file) setPicked({ folder, file })
    // A document just created from New may not be in the cached list yet:
    // only a list fresh from the server can say the file is not there.
    else if (!refetching) setFailure(folders.isError || files.isError ? 'loadFailed' : 'notFound')
  }, [picked, listsLoaded, refetching, folder, file, sharedFile?.state, folders.isError, files.isError])

  useEffect(() => {
    if (!picked) return
    const { folder: container, file: f } = picked
    // A file shared by itself has no folder key: its own is enough.
    if ((!container.key && container.source !== 'file') || !f.fileKey || !f.name) {
      setFailure('undecryptable')
      return
    }
    const name = f.name
    const target: SnapshotTarget = {
      fileKey: f.fileKey,
      context: { fileId: f.id, generation: f.keyGeneration },
    }
    const keyOf = (generation: number) => fileKeyAt(f, generation)

    let cancelled = false
    let blobUrl: string | null = null
    void (async () => {
      const location = fileLocation(container)
      const remote = location.kind !== 'local'
      // On another server, notes are edited live through this one
      // (docs/plans/collab-federation.md); office documents and whiteboards
      // are not yet.
      const viewer = chooseViewer(name)
      // A PDF you may change opens in ONLYOFFICE's PDF editor; one you may
      // only read (or on another server) in the viewer.
      const kind = editorKindFor(name) ?? (viewer?.kind === 'pdf' && container.canUpload && !remote ? 'office' : null)
      const editor = remote && kind !== 'text' ? null : kind
      // An editor writes only under the folder's current key: a file the
      // folder rotated past moves to it first (docs/plans/drive-share-revocation.md).
      if (editor && !remote && container.canUpload && f.keyEpoch < container.keyEpoch) {
        try {
          const rekeyed = await rekeyFile(container, f)
          void queryClient.invalidateQueries({ queryKey: filesKey(container.id) })
          if (!cancelled) setPicked({ folder: container, file: rekeyed })
        } catch {
          if (!cancelled) setFailure('loadFailed')
        }
        return
      }
      if (!editor && !viewer) {
        setKeys({ target, fileKeyAt: keyOf })
        setOpened({ kind: 'none' })
        return
      }
      if (f.size > MAX_OPEN_BYTES) {
        setFailure('tooLarge')
        return
      }
      try {
        let bytes: Uint8Array
        let base: SessionBase = { versionId: null, seq: 0 }
        // Each stored thing opens with the key generation it was sealed under.
        if (editor === 'office' || editor === 'whiteboard' || viewer?.kind === 'pdf') {
          // Reopen what was last saved, not the upload (a PDF edited in
          // ONLYOFFICE is saved as versions, and the viewer shows the latest).
          const content =
            editor === 'office' && openAt ? await contentAt(f, openAt.versionId) : await currentContent(container, f)
          if (content.kind === 'version') base = { versionId: content.versionId, seq: content.seqAtSnapshot }
          bytes =
            content.kind === 'version'
              ? await loadVersionBytes(await sealedAt(f, content.keyGeneration), content.path)
              : await loadOriginal(location, f, await sealedAt(f, f.contentKeyGeneration))
        } else {
          // Notes pick their latest version up themselves; the upload only
          // seeds a note that has never been edited.
          bytes = await loadOriginal(location, f, await sealedAt(f, f.contentKeyGeneration))
        }
        if (cancelled) return
        setKeys({ target, fileKeyAt: keyOf })
        if (editor === 'text') {
          setOpened({ kind: 'text', initialText: new TextDecoder().decode(bytes) })
        } else if (editor) {
          setOpened({ kind: editor, bytes, base })
        } else if (viewer) {
          blobUrl = URL.createObjectURL(new Blob([bytes as BlobPart], { type: viewer.mimeType }))
          setOpened({ kind: 'viewer', blobUrl, mimeType: viewer.mimeType })
        }
      } catch {
        if (!cancelled) setFailure('loadFailed')
      }
    })()
    return () => {
      cancelled = true
      if (blobUrl) URL.revokeObjectURL(blobUrl)
    }
  }, [picked, queryClient, reopen, openAt])

  // Live: the current name and permissions (a rename shows at once).
  const liveFolder = folder ?? picked?.folder
  const liveFile = file ?? picked?.file
  const name = liveFile?.name

  useEffect(() => {
    if (!name) return
    const previous = document.title
    document.title = `${name} · ${t('app.title')}`
    return () => {
      document.title = previous
    }
  }, [name, t])

  // The tab shows the file's kind (a sheet for a spreadsheet), as the lists do.
  const kind = name ? fileKind(name, liveFile?.mimeType) : null
  useEffect(() => {
    if (!kind) return
    const icon = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
    if (!icon) return
    const previous = { href: icon.href, type: icon.type }
    let current = true
    void kindTileSvg(kind).then((svg) => {
      if (!current) return
      icon.type = 'image/svg+xml'
      icon.href = `data:image/svg+xml,${encodeURIComponent(svg)}`
    }).catch(() => undefined)
    return () => {
      current = false
      icon.href = previous.href
      icon.type = previous.type
    }
  }, [kind])

  if (failure) return <FailurePanel failure={failure} folder={liveFolder} file={liveFile} />
  // An office document: the editor's converter and code download while the
  // file does (hidden, into the cache), instead of after it. First in the
  // tree, so it stays mounted (and its downloads go on) when the editor
  // opens. docs/research/18-web-performance.md.
  const warmType = officeWarmType(file, folder)
  const warm = warmType ? (
    <iframe
      key="warm"
      hidden
      aria-hidden
      tabIndex={-1}
      title=""
      src={appUrl('editor', `/onlyoffice/inner.html?${new URLSearchParams({ warm: '1', type: warmType }).toString()}`)}
    />
  ) : null

  if (!opened || !keys || !liveFolder || !liveFile || !name) {
    return (
      <>
        {warm}
        <div className="flex min-h-svh items-center justify-center bg-background">
          <LoadingPanel label={t('file.opening')} />
        </div>
      </>
    )
  }

  return (
    <>
      {warm}
      <Workspace
        // The editors take read-only when they are built: rebuild them when
        // this network turns out to block live editing (and when it stops).
        key={`${generation}:${liveBlocked ? 'blocked' : 'live'}`}
        folder={liveFolder}
        file={liveFile}
        name={name}
        opened={opened}
        keys={keys}
        // As the file opened: an editor stays one for the session (the server
        // drops a narrowed share's edits and closes its socket).
        readOnly={!(picked?.folder ?? liveFolder).canUpload || liveBlocked}
        liveBlocked={live !== 'live'}
        unsentEdits={live === 'blockedWithEdits'}
        notice={sharedFile?.state === 'editsWait' && sharedFile.canEdit ? t('file.editsWait') : null}
        shareRole={shareRole(liveFolder, liveFile, sharedFile)}
        sharedBy={
          sharedFile
            ? { sharer: sharedFile.sharerAccount, owner: sharedFile.ownerAccount }
            : liveFolder.source !== 'owned' && liveFolder.ownerAccount
              ? { sharer: liveFolder.ownerAccount, owner: liveFolder.ownerAccount }
              : null
        }
        mayRename={
          liveFolder.source === 'file'
            ? liveFolder.canUpload
            : liveFolder.canManage || (liveFolder.canDelete && liveFile.uploaderUserId === session.userId)
        }
        onRestored={(bytes, base) => {
          if (opened.kind === 'office' || opened.kind === 'whiteboard') {
            setOpenAt(null)
            setOpened({ kind: opened.kind, bytes, base, resetBase: true })
            setGeneration((g) => g + 1)
          }
        }}
        onOutdated={(base) => {
          setOpenAt(base ?? null)
          setOpened(null)
          setReopen((n) => n + 1)
        }}
      />
    </>
  )
}

/**
 * The editor files worth fetching ahead for `file`: an office document here
 * (not on another server), on the Office site — elsewhere it is about to
 * move there, and only Office may frame the sandbox.
 */
function officeWarmType(file: DriveFile | undefined, folder: Folder | undefined): 'docx' | 'xlsx' | 'pptx' | null {
  if (!file?.name || !folder || fileLocation(folder).kind !== 'local' || currentApp() !== 'office') return null
  const ext = file.name.slice(file.name.lastIndexOf('.') + 1).toLowerCase()
  return ext === 'docx' || ext === 'xlsx' || ext === 'pptx' ? ext : null
}

async function loadOriginal(location: FileLocation, file: DriveFile, target: SnapshotTarget): Promise<Uint8Array> {
  const { data } = await api.get<ArrayBuffer>(contentPath(location, file.id), { responseType: 'arraybuffer' })
  return decryptFileBlobV1(new Uint8Array(data), target.fileKey, target.context)
}

function useDownload(folder: Folder | undefined, file: DriveFile | undefined) {
  const { t } = useTranslation()
  return useCallback(async () => {
    if (!folder || !file) return
    try {
      await downloadFile(folder, file)
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return
      toast.error(error instanceof FsaRequiredError ? t('file.zipTooLarge') : t('file.downloadFailed'))
    }
  }, [folder, file, t])
}

/**
 * Where the back button goes: to the app the file was opened from (`?from=`,
 * only `drive` or `office`, so the parameter cannot send anyone elsewhere),
 * or else this app's own place for it — Office's home, or the file's folder
 * in Drive.
 */
function useBack(folder: Folder | undefined): { app: 'drive' | 'office'; path: string; label: string } {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const app = openedFrom(params.get('from')) ?? currentApp()
  if (app === 'office') return { app, path: '/', label: t('file.backToOffice') }
  if (!folder) return { app, path: '/', label: t('file.backToDrive') }
  return {
    app,
    path: folderPath(folder),
    label: t('file.backTo', {
      folder: folder.isRoot ? t('file.myFiles') : folder.source === 'file' ? t('file.sharedWithMe') : folder.name,
    }),
  }
}

/** A link back: within this app, or to the other one. */
function BackLink({ back, children, labelled }: { back: ReturnType<typeof useBack>; children: ReactNode; labelled?: boolean }) {
  const label = labelled ? back.label : undefined
  return back.app === currentApp() ? (
    <Link to={back.path} aria-label={label}>
      {children}
    </Link>
  ) : (
    <a href={appUrl(back.app, back.path)} aria-label={label}>
      {children}
    </a>
  )
}

function FailurePanel({ failure, folder, file }: { failure: Failure; folder?: Folder; file?: DriveFile }) {
  const { t, i18n } = useTranslation()
  const back = useBack(folder)
  const download = useDownload(folder, file)
  const description =
    failure === 'tooLarge'
      ? t('file.tooLarge', {
          size: formatBytes(file?.size ?? 0, i18n.language),
          limit: formatBytes(MAX_OPEN_BYTES, i18n.language),
        })
      : t(`file.${failure}`)
  return (
    <div className="flex min-h-svh items-center justify-center bg-background p-6">
      <div className="max-w-md space-y-4 text-center">
        <h1 className="text-lg font-semibold">{t('file.failedTitle')}</h1>
        <p className="text-sm text-muted-foreground">{description}</p>
        <div className="flex flex-wrap justify-center gap-2">
          <Button variant="outline" asChild>
            <BackLink back={back}>
              <ArrowLeft /> {back.app === 'office' ? t('file.backToOffice') : t('file.backToDrive')}
            </BackLink>
          </Button>
          {failure === 'tooLarge' ? (
            <Button onClick={() => void download()}>
              <Download /> {t('file.actions.download')}
            </Button>
          ) : null}
        </div>
      </div>
    </div>
  )
}

function Workspace({
  folder,
  file,
  name,
  opened,
  keys,
  readOnly,
  liveBlocked,
  unsentEdits,
  notice,
  shareRole: mayShare,
  sharedBy,
  mayRename,
  onRestored,
  onOutdated,
}: {
  folder: Folder
  file: DriveFile
  name: string
  opened: Opened
  keys: Keys
  /** A view-only share: editors open read-only, nothing is saved. */
  readOnly: boolean
  /** This network blocks live editing: say so above the document. */
  liveBlocked: boolean
  /** …and edits made here are still waiting to be sent. */
  unsentEdits: boolean
  /** Why an editor opened read-only when that is not its share. */
  notice: string | null
  /** How this account may share the file from here, if at all. */
  shareRole: ShareRole | null
  /** Someone else's file: who shared it with this account, and whose it is. */
  sharedBy: { sharer: string; owner: string } | null
  mayRename: boolean
  onRestored: (bytes: Uint8Array, base: SessionBase) => void
  /** The office session's base is another version: reopen from it. */
  onOutdated: (base?: SessionBase) => void
}) {
  const { t } = useTranslation()
  const back = useBack(folder)
  const download = useDownload(folder, file)
  const rename = useRenameFile()
  const [renaming, setRenaming] = useState(false)
  const [sharing, setSharing] = useState(false)
  const officeRef = useRef<OfficeEditorHandle | null>(null)
  const whiteboardRef = useRef<WhiteboardEditorHandle | null>(null)
  // OnlyOffice runs in a frame and reports its own Ctrl+S; WholeFileActions
  // owns saving and fills this in.
  const saveShortcut = useRef<(() => void) | null>(null)
  const wholeFile: EditorKind | null =
    opened.kind === 'office' || opened.kind === 'whiteboard' ? opened.kind : null

  const editor = (() => {
    const common = {
      fileId: file.id,
      filename: name,
      fileKey: keys.target.fileKey,
      keyGeneration: keys.target.context.generation,
      fileKeyAt: keys.fileKeyAt,
    }
    switch (opened.kind) {
      case 'text': {
        const location = fileLocation(folder)
        return (
          <TextCollabEditor
            {...common}
            initialContent={opened.initialText}
            readOnly={readOnly}
            base={location.kind === 'local' ? undefined : collabBase(location, file.id)}
          />
        )
      }
      case 'office':
        return (
          <OfficeEditor
            ref={officeRef}
            {...common}
            initialBytes={opened.bytes}
            base={opened.base}
            resetBase={opened.resetBase}
            onOutdated={onOutdated}
            onSaveShortcut={() => saveShortcut.current?.()}
            readOnly={readOnly}
          />
        )
      case 'whiteboard':
        return <WhiteboardEditor ref={whiteboardRef} {...common} initialBytes={opened.bytes} readOnly={readOnly} />
      case 'viewer': {
        const viewer = chooseViewer(name)
        return viewer ? <viewer.Component filename={name} blobUrl={opened.blobUrl} mimeType={opened.mimeType} /> : null
      }
      case 'none':
        return <NoPreview onDownload={() => void download()} />
    }
  })()

  return (
    <div className="flex h-svh flex-col overflow-hidden bg-background">
      <header className="flex h-12 shrink-0 items-center gap-2 border-b border-border bg-background/95 px-2 sm:px-3">
        <Button variant="ghost" size="icon" asChild>
          <BackLink back={back} labelled>
            <ArrowLeft />
          </BackLink>
        </Button>
        <KutupLogo size={22} className="hidden shrink-0 sm:block" />
        {mayRename ? (
          <button
            type="button"
            onClick={() => setRenaming(true)}
            title={t('file.actions.rename')}
            className="min-w-0 truncate rounded px-1.5 py-1 text-sm font-medium hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {name}
          </button>
        ) : (
          <span className="min-w-0 truncate px-1.5 text-sm font-medium">{name}</span>
        )}
        {sharedBy ? <SharedBy {...sharedBy} /> : null}
        <div className="ml-auto flex shrink-0 items-center gap-1.5">
          {notice ? (
            <span className="hidden rounded-full bg-muted px-2.5 py-1 text-xs font-medium text-muted-foreground sm:inline" title={notice}>
              {notice}
            </span>
          ) : null}
          {wholeFile && readOnly ? (
            <ViewOnlyActions fileId={file.id} />
          ) : wholeFile ? (
            <WholeFileActions
              openVersion={async (versionId) => {
                // A version opens with the key generation it was saved under.
                const version = (await listVersions(file.id)).find((v) => v.id === versionId)
                if (!version) throw new Error('version not found')
                return loadVersionBytes(
                  await sealedAt(file, version.keyGeneration),
                  `/files/${file.id}/versions/${versionId}/download`,
                )
              }}
              kind={wholeFile}
              keys={keys}
              saveShortcut={saveShortcut}
              getBytes={async () =>
                wholeFile === 'office'
                  ? (await officeRef.current!.save()).bytes
                  : (await whiteboardRef.current!.save()).bytes
              }
              officePdf={
                wholeFile === 'office'
                  ? () => officeRef.current?.thumbnailPdf() ?? Promise.reject(new Error('editor closed'))
                  : undefined
              }
              isSpreadsheet={extensionOf(name) === 'xlsx'}
              logPosition={wholeFile === 'office' ? () => officeRef.current?.logPosition() ?? null : undefined}
              onRestored={onRestored}
            />
          ) : null}
          {opened.kind === 'office' ? <EditorNotice /> : null}
          {mayShare ? (
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setSharing(true)}
              title={t('file.actions.share')}
              aria-label={t('file.actions.share')}
            >
              <UserPlus />
            </Button>
          ) : null}
          <Button
            variant="ghost"
            size="icon"
            onClick={() => void download()}
            title={t('file.actions.download')}
            aria-label={t('file.actions.download')}
          >
            <Download />
          </Button>
          <div className="hidden sm:block">
            <ThemeToggle onChrome={false} />
          </div>
        </div>
      </header>
      {liveBlocked && (wholeFile || opened.kind === 'text') ? (
        <div role="status" data-testid="editor-live-blocked" className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1 border-b border-border bg-muted/60 px-3 py-2 text-sm">
          <WifiOff className="size-4 shrink-0 text-muted-foreground" aria-hidden />
          <p className="min-w-0 flex-1">
            <span className="font-medium">{t('file.liveBlocked')}</span>{' '}
            <span className="text-muted-foreground">{t(unsentEdits ? 'file.liveBlockedUnsent' : 'file.liveBlockedBody')}</span>
          </p>
          <Button size="sm" variant="outline" onClick={() => void download()}>
            <Download />
            {t('file.actions.download')}
          </Button>
        </div>
      ) : null}
      <div className="min-h-0 flex-1">
        <Suspense fallback={<LoadingPanel label={t('file.opening')} />}>{editor}</Suspense>
      </div>
      <NameDialog
        open={renaming}
        title={t('file.rename.title')}
        initial={name}
        submit={t('file.rename.submit')}
        pending={rename.isPending}
        error={rename.error}
        onClose={() => (setRenaming(false), rename.reset())}
        onSubmit={(next) => rename.mutate({ folder, file, name: next }, { onSuccess: () => setRenaming(false) })}
      />
      <FileShareDialog
        target={sharing && mayShare ? { folder, file, role: mayShare } : null}
        onClose={() => setSharing(false)}
      />
    </div>
  )
}

/** Who shared the file (by their name once they gave it), beside its name. */
function SharedBy({ sharer, owner }: { sharer: string; owner: string }) {
  const { t } = useTranslation()
  const people = usePeople()
  const sharerName = personOf(people.data, sharer).name
  const ownerName = personOf(people.data, owner).name
  return (
    <span
      data-testid="file-shared-by"
      className="hidden min-w-0 truncate text-xs text-muted-foreground md:inline"
      title={sharer !== owner ? t('file.sharedByOwner', { sharer: sharerName, owner: ownerName }) : sharer}
    >
      {t('file.sharedBy', { name: sharerName })}
    </span>
  )
}

function NoPreview({ onDownload }: { onDownload: () => void }) {
  const { t } = useTranslation()
  return (
    <div className="flex h-full items-center justify-center p-6">
      <div className="max-w-sm space-y-3 text-center">
        <p className="font-medium">{t('file.noPreviewTitle')}</p>
        <p className="text-sm text-muted-foreground">{t('file.noPreview')}</p>
        <Button onClick={onDownload}>
          <Download /> {t('file.actions.download')}
        </Button>
      </div>
    </div>
  )
}

/**
 * Save, Save version and History for the editors that save the whole file.
 * (The text editor carries its own, driven by its Yjs snapshots.)
 */
function WholeFileActions({
  openVersion,
  kind,
  keys,
  saveShortcut,
  getBytes,
  officePdf,
  isSpreadsheet = false,
  logPosition,
  onRestored,
}: {
  /** A stored version's plaintext. */
  openVersion: (versionId: string) => Promise<Uint8Array>
  kind: EditorKind
  keys: Keys
  saveShortcut: MutableRefObject<(() => void) | null>
  getBytes: () => Promise<Uint8Array>
  /** Office only: the document laid out as a PDF, for its thumbnail. */
  officePdf?: () => Promise<Uint8Array>
  /** Its thumbnail is cropped to the used cells. */
  isSpreadsheet?: boolean
  /** Office only: where the editor is in the collaboration log. */
  logPosition?: () => LogPosition | null
  onRestored: (bytes: Uint8Array, base: SessionBase) => void
}) {
  const { t } = useTranslation()
  const [saving, setSaving] = useState(false)
  const [justSaved, setJustSaved] = useState(false)
  const [naming, setNaming] = useState(false)
  const [historyOpen, setHistoryOpen] = useState(false)
  const [restoring, setRestoring] = useState<string | null>(null)
  const savingRef = useRef(false)
  // What the last save stored, so saving unchanged content stores nothing
  // (and naming it names that version, as CryptPad's snapshots do).
  const lastSaved = useRef<{ digest: string; versionId: string } | null>(null)

  const save = useCallback(
    async (opts: { label?: string; keepForever?: boolean; quiet?: boolean } = {}) => {
      if (savingRef.current) return false
      savingRef.current = true
      setSaving(true)
      try {
        // Read before the bytes: every edit up to here is in them (one that
        // lands in between is in them too, and replays harmlessly on top).
        const position = logPosition?.() ?? null
        const bytes = await getBytes()
        const digest = await sha256(bytes)
        const previous = lastSaved.current
        if (previous && previous.digest === digest) {
          if (opts.label) {
            await patchVersion(keys.target.context.fileId, previous.versionId, {
              label: opts.label,
              keepForever: Boolean(opts.keepForever),
            })
          }
          if (!opts.quiet) {
            setJustSaved(true)
            setTimeout(() => setJustSaved(false), 1500)
          }
          return true
        }
        const { id: versionId } = await saveSnapshot(keys.target, bytes, { ...opts, position })
        lastSaved.current = { digest, versionId }
        if (kind === 'whiteboard') redrawWhiteboard(keys.target, versionId, bytes)
        if (kind === 'office' && officePdf) redrawOffice(keys.target, versionId, officePdf, isSpreadsheet)
        if (!opts.quiet) {
          setJustSaved(true)
          setTimeout(() => setJustSaved(false), 1500)
        }
        return true
      } catch (error) {
        if (!opts.quiet) toast.error(error instanceof QuotaExceededError ? t('editor.quotaSave') : t('common.tryAgain'))
        return false
      } finally {
        savingRef.current = false
        setSaving(false)
      }
    },
    [getBytes, keys.target, kind, officePdf, isSpreadsheet, logPosition, t],
  )

  // Ctrl/Cmd+S anywhere on the page. OnlyOffice runs in a frame and forwards
  // its own Ctrl+S; the whiteboard is a plain React canvas.
  const saveRef = useRef(save)
  saveRef.current = save
  useEffect(() => {
    saveShortcut.current = () => void saveRef.current()
    return () => {
      saveShortcut.current = null
    }
  }, [saveShortcut])
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === 's') {
        e.preventDefault()
        void saveRef.current()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  async function restore(versionId: string, choice: RestoreChoice) {
    const id = toast.loading(t('file.restoring'))
    try {
      const old = await openVersion(versionId)
      const time = new Date().toLocaleString()
      if (choice === 'save-and-restore') {
        await save({ label: t('editor.preRestoreLabel', { time }), quiet: true })
      }
      // Restoring appends: the old content becomes the newest version, and
      // the log so far (edits to what it replaces) is behind it.
      const position = logPosition?.() ?? null
      const restored = await saveSnapshot(keys.target, old, { label: t('editor.restoredLabel', { time }), position })
      toast.success(t('editor.restored'), { id })
      onRestored(old, { versionId: restored.id, seq: restored.seqAtSnapshot })
    } catch (error) {
      toast.error(error instanceof QuotaExceededError ? t('editor.quotaSave') : t('editor.restoreFailed'), { id })
    }
  }

  const [color, changeColor] = useCursorColor()

  return (
    <>
      {/* Excalidraw colours peers by its own hash of their id and ignores
          the colour we pass, so the picker only means something in office. */}
      {kind === 'office' ? <CursorColorPicker color={color} onChange={changeColor} /> : null}
      <Button size="sm" variant="outline" disabled={saving} onClick={() => void save()} title={t('editor.saveHint')}>
        {justSaved ? <Check className="text-primary" /> : <Save />}
        <span className="hidden md:inline">
          {saving ? t('editor.saving') : justSaved ? t('editor.saved') : t('editor.save')}
        </span>
      </Button>
      <Button
        size="sm"
        variant="outline"
        disabled={saving}
        onClick={() => setNaming(true)}
        title={t('editor.saveVersionHint')}
        className="hidden sm:inline-flex"
      >
        <BookmarkPlus />
        <span className="hidden md:inline">{t('editor.saveVersion')}</span>
      </Button>
      <Button
        size="sm"
        variant={historyOpen ? 'default' : 'outline'}
        onClick={() => setHistoryOpen((v) => !v)}
        aria-pressed={historyOpen}
        title={t('editor.historyTitle')}
      >
        <History />
        <span className="hidden md:inline">{t('editor.history')}</span>
      </Button>

      {historyOpen ? (
        <HistoryDrawer onClose={() => setHistoryOpen(false)}>
          <VersionHistoryPanel fileId={keys.target.context.fileId} onRestore={setRestoring} />
        </HistoryDrawer>
      ) : null}

      <NameDialog
        open={naming}
        title={t('editor.nameVersion.title')}
        description={t('editor.nameVersion.description')}
        initial=""
        submit={t('editor.saveVersion')}
        pending={saving}
        error={null}
        onClose={() => setNaming(false)}
        onSubmit={(label) => {
          void save({ label, keepForever: true }).then((saved) => saved && setNaming(false))
        }}
      />
      <RestoreConfirmDialog
        open={restoring !== null}
        onCancel={() => setRestoring(null)}
        onChoose={(choice) => {
          const versionId = restoring
          setRestoring(null)
          if (versionId) void restore(versionId, choice)
        }}
      />
    </>
  )
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource))
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** A saved whiteboard's thumbnail, drawn from the scene that was saved. */
function redrawWhiteboard(target: SnapshotTarget, versionId: string, bytes: Uint8Array): void {
  const json = new TextDecoder().decode(bytes)
  enqueueThumbnail(target.context.fileId, async () => {
    const png = await exportScene(json)
    if (!png) return false
    return storeThumbnails(
      { fileId: target.context.fileId, fileKey: target.fileKey, keyGeneration: target.context.generation },
      await thumbnailsOfDrawing(png),
      versionId,
    )
  })
}

/**
 * A saved office document's thumbnail: OnlyOffice lays it out as a PDF in
 * its sandbox (print → x2t), and page one is drawn here with PDF.js.
 */
function redrawOffice(target: SnapshotTarget, versionId: string, pdf: () => Promise<Uint8Array>, trim: boolean): void {
  enqueueThumbnail(target.context.fileId, async () => {
    const bytes = await pdf()
    // Printed with gridlines: its top-left corner, at a size cells can be read.
    const png = await renderPdfFirstPageV1(bytes.slice().buffer, THUMBNAIL_MAX_SIDE.lg, undefined, trim ? { trim: 'corner' } : {})
    if (!png) return false
    return storeThumbnails(
      { fileId: target.context.fileId, fileKey: target.fileKey, keyGeneration: target.context.generation },
      await thumbnailsOfPicture(png, true),
      versionId,
    )
  })
}

/**
 * What a viewer gets instead of Save: a note that the file is view-only,
 * and the history to look through.
 */
function ViewOnlyActions({ fileId }: { fileId: string }) {
  const { t } = useTranslation()
  const [historyOpen, setHistoryOpen] = useState(false)
  return (
    <>
      <span className="inline-flex items-center gap-1.5 rounded-full bg-muted px-2.5 py-1 text-xs font-medium text-muted-foreground">
        <Eye className="size-3.5" aria-hidden /> {t('editor.viewOnly')}
      </span>
      <Button
        size="sm"
        variant={historyOpen ? 'default' : 'outline'}
        onClick={() => setHistoryOpen((v) => !v)}
        aria-pressed={historyOpen}
        title={t('editor.historyTitle')}
      >
        <History />
        <span className="hidden md:inline">{t('editor.history')}</span>
      </Button>
      {historyOpen ? (
        <HistoryDrawer onClose={() => setHistoryOpen(false)}>
          <VersionHistoryPanel fileId={fileId} readOnly />
        </HistoryDrawer>
      ) : null}
    </>
  )
}

/** The version list, over the editor's right edge below the header. */
function HistoryDrawer({ onClose, children }: { onClose: () => void; children: ReactNode }) {
  const { t } = useTranslation()
  return (
    <aside className="fixed bottom-0 right-0 top-12 z-30 flex w-full max-w-[360px] flex-col border-l border-border bg-card shadow-lg">
      <header className="flex h-12 shrink-0 items-center justify-between border-b border-border px-4">
        <h2 className="text-sm font-semibold">{t('editor.historyTitle')}</h2>
        <Button size="icon" variant="ghost" onClick={onClose} aria-label={t('editor.closeHistory')}>
          <X />
        </Button>
      </header>
      <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain">{children}</div>
    </aside>
  )
}
