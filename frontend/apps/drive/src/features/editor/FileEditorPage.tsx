import { ArrowLeft, BookmarkPlus, Check, Download, History, Save, X } from 'lucide-react'
import { Suspense, useCallback, useEffect, useRef, useState, type MutableRefObject, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { decryptFileBlobV1 } from '@kutup/crypto/fileBlob'
import { QuotaExceededError } from '@kutup/session/errors'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'
import { KutupLogo } from '@kutup/ui/components/brand'
import { Button } from '@kutup/ui/components/button'
import { LoadingPanel } from '@kutup/ui/components/states'
import { ThemeToggle } from '@kutup/ui/components/theme-toggle'
import { formatBytes } from '@kutup/ui/lib/format'
import { NameDialog } from '../dialogs/NameDialog'
import { downloadFile, FsaRequiredError } from '../drive/downloads'
import { useFolderFiles } from '../drive/files'
import { useFolders } from '../drive/folders'
import { useRenameFile } from '../drive/mutations'
import type { DriveFile, Folder } from '../drive/model'
import { folderPath } from '../drive/paths'
import { currentContent } from './content'
import CursorColorPicker from './CursorColorPicker'
import { OfficeEditor, TextCollabEditor, WhiteboardEditor } from './dispatch'
import { editorKindFor, extensionOf, type EditorKind } from './editorKind'
import type { OfficeEditorHandle } from './office/OfficeEditor'
import { patchVersion } from '@kutup/collab/api'
import { loadVersionBytes, saveSnapshot, type SnapshotTarget } from './snapshots'
import { renderPdfFirstPageV1 } from '@kutup/files/mediaPreview'
import { THUMBNAIL_MAX_SIDE } from '@kutup/crypto/thumbnail'
import { exportScene, thumbnailsOfDrawing, thumbnailsOfPicture } from '../thumbnails/make'
import { enqueueThumbnail } from '../thumbnails/queue'
import { storeThumbnails } from '../thumbnails/store'
import RestoreConfirmDialog, { type RestoreChoice } from './versions/RestoreConfirmDialog'
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
  | { kind: 'office' | 'whiteboard'; bytes: Uint8Array }
  | { kind: 'viewer'; blobUrl: string; mimeType: string }
  /** Nothing in the browser opens it: offer the download. */
  | { kind: 'none' }

type Failure = 'notFound' | 'undecryptable' | 'tooLarge' | 'loadFailed'

interface Keys {
  collectionKey: Uint8Array
  target: SnapshotTarget
}

/**
 * `/file/:cid/:fid`: one file, full screen. Notes and code open in the
 * collaborative text editor, office documents in OnlyOffice, whiteboards in
 * Excalidraw; images, PDFs and media in a viewer; anything else offers its
 * download. Keyed by the file, so moving to another file starts afresh.
 */
export function FileEditorPage() {
  const { cid = '', fid = '' } = useParams()
  return <OpenFile key={`${cid}/${fid}`} cid={cid} fid={fid} />
}

function OpenFile({ cid, fid }: { cid: string; fid: string }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const folders = useFolders()
  const folder = folders.data?.byId.get(cid)
  const files = useFolderFiles(folder)
  const file = files.data?.find((f) => f.id === fid)

  // The folder and file as they were when the file opened. Their keys are
  // what the editors hold: a rename refetches the list, which decrypts fresh
  // key copies, and handing those over would tear the editors' sessions down
  // for nothing. Names and permissions are read live below.
  const [picked, setPicked] = useState<{ folder: Folder; file: DriveFile } | null>(null)
  const [opened, setOpened] = useState<Opened | null>(null)
  const [keys, setKeys] = useState<Keys | null>(null)
  const [failure, setFailure] = useState<Failure | null>(null)
  // Bumped to remount a whole-file editor on restored content.
  const [generation, setGeneration] = useState(0)

  const listsLoaded = folders.isSuccess && (!folder?.key || files.isSuccess)
  const refetching = folders.isFetching || files.isFetching
  useEffect(() => {
    if (picked || !listsLoaded) return
    if (folder && file) setPicked({ folder, file })
    // A document just created from New may not be in the cached list yet:
    // only a list fresh from the server can say the file is not there.
    else if (!refetching) setFailure(folders.isError || files.isError ? 'loadFailed' : 'notFound')
  }, [picked, listsLoaded, refetching, folder, file, folders.isError, files.isError])

  useEffect(() => {
    if (!picked) return
    const { folder: container, file: f } = picked
    if (!container.key || !f.fileKey || !f.name) {
      setFailure('undecryptable')
      return
    }
    const collectionKey = container.key
    const name = f.name
    const target: SnapshotTarget = {
      fileKey: f.fileKey,
      context: { fileId: f.id, collectionId: f.collectionId, epoch: f.keyEpoch },
    }

    let cancelled = false
    let blobUrl: string | null = null
    void (async () => {
      const editor = container.source === 'remote' ? null : editorKindFor(name)
      const viewer = container.source === 'remote' ? null : chooseViewer(name)
      if (!editor && !viewer) {
        setKeys({ collectionKey, target })
        setOpened({ kind: 'none' })
        return
      }
      if (f.size > MAX_OPEN_BYTES) {
        setFailure('tooLarge')
        return
      }
      try {
        let bytes: Uint8Array
        if (editor === 'office' || editor === 'whiteboard') {
          // Reopen what was last saved, not the upload.
          const content = await currentContent(f)
          bytes =
            content.kind === 'version'
              ? await loadVersionBytes(target, content.path)
              : await loadOriginal(f, target)
        } else {
          // Notes pick their latest version up themselves; the upload only
          // seeds a note that has never been edited.
          bytes = await loadOriginal(f, target)
        }
        if (cancelled) return
        setKeys({ collectionKey, target })
        if (editor === 'text') {
          setOpened({ kind: 'text', initialText: new TextDecoder().decode(bytes) })
        } else if (editor) {
          setOpened({ kind: editor, bytes })
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
  }, [picked])

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

  if (failure) return <FailurePanel failure={failure} folder={liveFolder} file={liveFile} />
  if (!opened || !keys || !liveFolder || !liveFile || !name) {
    return (
      <div className="flex min-h-svh items-center justify-center bg-background">
        <LoadingPanel label={t('file.opening')} />
      </div>
    )
  }

  return (
    <Workspace
      key={generation}
      folder={liveFolder}
      file={liveFile}
      name={name}
      opened={opened}
      keys={keys}
      mayRename={liveFolder.canManage || (liveFolder.canDelete && liveFile.uploaderUserId === session.userId)}
      onRestored={(bytes) => {
        if (opened.kind === 'office' || opened.kind === 'whiteboard') {
          setOpened({ kind: opened.kind, bytes })
          setGeneration((g) => g + 1)
        }
      }}
    />
  )
}

async function loadOriginal(file: DriveFile, target: SnapshotTarget): Promise<Uint8Array> {
  const { data } = await api.get<ArrayBuffer>(`/files/${file.id}/download`, { responseType: 'arraybuffer' })
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
      toast.error(error instanceof FsaRequiredError ? t('drive.zipTooLarge') : t('drive.downloadFailed'))
    }
  }, [folder, file, t])
}

function FailurePanel({ failure, folder, file }: { failure: Failure; folder?: Folder; file?: DriveFile }) {
  const { t, i18n } = useTranslation()
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
            <Link to={folder ? folderPath(folder) : '/'}>
              <ArrowLeft /> {t('file.backToDrive')}
            </Link>
          </Button>
          {failure === 'tooLarge' ? (
            <Button onClick={() => void download()}>
              <Download /> {t('drive.actions.download')}
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
  mayRename,
  onRestored,
}: {
  folder: Folder
  file: DriveFile
  name: string
  opened: Opened
  keys: Keys
  mayRename: boolean
  onRestored: (bytes: Uint8Array) => void
}) {
  const { t } = useTranslation()
  const download = useDownload(folder, file)
  const rename = useRenameFile()
  const [renaming, setRenaming] = useState(false)
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
      collectionId: file.collectionId,
      filename: name,
      collectionMaster: keys.collectionKey,
      keyEpoch: keys.target.context.epoch,
    }
    switch (opened.kind) {
      case 'text':
        return <TextCollabEditor {...common} fileKey={keys.target.fileKey} initialContent={opened.initialText} />
      case 'office':
        return (
          <OfficeEditor
            ref={officeRef}
            {...common}
            initialBytes={opened.bytes}
            onSaveShortcut={() => saveShortcut.current?.()}
          />
        )
      case 'whiteboard':
        return <WhiteboardEditor ref={whiteboardRef} {...common} initialBytes={opened.bytes} />
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
          <Link to={folderPath(folder)} aria-label={t('file.backTo', { folder: folder.isRoot ? t('nav.myFiles') : folder.name })}>
            <ArrowLeft />
          </Link>
        </Button>
        <KutupLogo size={22} className="hidden shrink-0 sm:block" />
        {mayRename ? (
          <button
            type="button"
            onClick={() => setRenaming(true)}
            title={t('drive.actions.rename')}
            className="min-w-0 truncate rounded px-1.5 py-1 text-sm font-medium hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {name}
          </button>
        ) : (
          <span className="min-w-0 truncate px-1.5 text-sm font-medium">{name}</span>
        )}
        <div className="ml-auto flex shrink-0 items-center gap-1.5">
          {wholeFile ? (
            <WholeFileActions
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
              onRestored={onRestored}
            />
          ) : null}
          <Button
            variant="ghost"
            size="icon"
            onClick={() => void download()}
            title={t('drive.actions.download')}
            aria-label={t('drive.actions.download')}
          >
            <Download />
          </Button>
          <div className="hidden sm:block">
            <ThemeToggle onChrome={false} />
          </div>
        </div>
      </header>
      <div className="min-h-0 flex-1">
        <Suspense fallback={<LoadingPanel label={t('file.opening')} />}>{editor}</Suspense>
      </div>
      <NameDialog
        open={renaming}
        title={t('dialogs.rename.title')}
        initial={name}
        submit={t('dialogs.rename.submit')}
        pending={rename.isPending}
        error={rename.error}
        onClose={() => (setRenaming(false), rename.reset())}
        onSubmit={(next) => rename.mutate({ file, name: next }, { onSuccess: () => setRenaming(false) })}
      />
    </div>
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
          <Download /> {t('drive.actions.download')}
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
  kind,
  keys,
  saveShortcut,
  getBytes,
  officePdf,
  isSpreadsheet = false,
  onRestored,
}: {
  kind: EditorKind
  keys: Keys
  saveShortcut: MutableRefObject<(() => void) | null>
  getBytes: () => Promise<Uint8Array>
  /** Office only: the document laid out as a PDF, for its thumbnail. */
  officePdf?: () => Promise<Uint8Array>
  /** Its thumbnail is cropped to the used cells. */
  isSpreadsheet?: boolean
  onRestored: (bytes: Uint8Array) => void
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
        const versionId = await saveSnapshot(keys.target, bytes, opts)
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
    [getBytes, keys.target, kind, officePdf, isSpreadsheet, t],
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
      const old = await loadVersionBytes(keys.target, `/files/${keys.target.context.fileId}/versions/${versionId}/download`)
      const time = new Date().toLocaleString()
      if (choice === 'save-and-restore') {
        await save({ label: t('editor.preRestoreLabel', { time }), quiet: true })
      }
      // Restoring appends: the old content becomes the newest version.
      await saveSnapshot(keys.target, old, { label: t('editor.restoredLabel', { time }) })
      toast.success(t('editor.restored'), { id })
      onRestored(old)
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
      { fileId: target.context.fileId, fileKey: target.fileKey, keyEpoch: target.context.epoch },
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
      { fileId: target.context.fileId, fileKey: target.fileKey, keyEpoch: target.context.epoch },
      await thumbnailsOfPicture(png, true),
      versionId,
    )
  })
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
