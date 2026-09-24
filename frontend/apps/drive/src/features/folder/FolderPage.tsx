import { CheckCheck, Copy, Download, ExternalLink, Eye, FolderInput, Link2, Palette, Pencil, Trash2, UserPlus, X } from 'lucide-react'
import { useCallback, useMemo, useState, type DragEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { dataTransferToFolderEntries } from '@kutup/files/upload/uploadFolder'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Breadcrumb, type Crumb } from '@kutup/ui/components/breadcrumb'
import { Button } from '@kutup/ui/components/button'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { useCreateActions } from '../create/useCreateActions'
import { ColorDialog } from '../dialogs/ColorDialog'
import { FolderPickerDialog } from '../dialogs/FolderPickerDialog'
import { LinkDialog } from '../dialogs/LinkDialog'
import { NameDialog } from '../dialogs/NameDialog'
import { ShareDialog } from '../dialogs/ShareDialog'
import { folderHex } from '../drive/colors'
import { useDeclareCurrentFolder } from '../drive/currentFolderContext'
import { isWithin } from '../drive/copy'
import { downloadFile, downloadFolderZip, downloadSelectionZip, FsaRequiredError } from '../drive/downloads'
import { useFolderFiles } from '../drive/files'
import { useFolders, type FolderIndex } from '../drive/folders'
import type { DriveFile, Folder } from '../drive/model'
import { useCreatePublicLink, useRenameFile, useRenameFolder, useTrashFile, useTrashFolder } from '../drive/mutations'
import { filePath, folderPath } from '../drive/paths'
import { moveRefusal, type MoveRefusal } from '../drive/move'
import { useCopy } from '../drive/useCopy'
import { useMove } from '../drive/useMove'
import { draggedItems, endItemDrag } from '../explorer/dragItems'
import { Explorer, type ExplorerAction } from '../explorer/Explorer'
import { ExplorerContextMenu, type ContextMenuSpec } from '../explorer/ExplorerContextMenu'
import { useExplorerPrefs } from '../explorer/prefs'
import { filterItems, itemKey, sortItems, type ExplorerItem } from '../explorer/sort'
import { Toolbar } from '../explorer/Toolbar'
import { QuickLook, type QuickLookTarget } from '../quicklook/QuickLook'
import { FileThumbnail } from '../thumbnails/FileThumbnail'
import { useUploadActions } from '../uploads/useUploadActions'

type Target = { folder: Folder; file?: undefined } | { folder: Folder; file: DriveFile }
type Dialog =
  | { kind: 'rename'; target: Target }
  | { kind: 'color'; folder: Folder }
  | { kind: 'share'; folder: Folder }
  | { kind: 'link'; url: string }
  | { kind: 'invite'; url: string; account: string }
  | { kind: 'copy'; targets: Target[] }
  | { kind: 'move'; targets: Target[] }
  | null

/**
 * Whether an item can be moved at all (docs/plans/drive-move.md): a file by
 * whoever can edit its folder, a folder by its owner. Where it may go is
 * `moveRefusal`'s to say.
 */
function mayMove(target: Target): boolean {
  if (target.file) return target.folder.source !== 'remote' && target.folder.canUpload && Boolean(target.file.fileKey)
  return target.folder.source === 'owned' && target.folder.canManage && !target.folder.isRoot && Boolean(target.folder.key)
}

/** Why none of `targets` can go into `dest`, or null when they can. */
function refusalFor(index: FolderIndex, targets: Target[], dest: Folder): MoveRefusal | null {
  const reasons = targets.map((target) => moveRefusal(index, target, dest))
  const blocking = reasons.find((r) => r !== null && r !== 'alreadyThere')
  if (blocking) return blocking
  // Some already there and some not: the rest move.
  return reasons.every((r) => r === 'alreadyThere') ? 'alreadyThere' : null
}

function resolveFolder(index: FolderIndex, id: string | undefined, shareId: string | undefined): Folder | undefined {
  if (shareId) return index.sharedWithMe.find((f) => f.remoteShareId === shareId)
  if (!id) return index.root
  return index.byId.get(id)
}

function crumbsFor(
  index: FolderIndex,
  folder: Folder,
  t: (k: string) => string,
  dropOn: (dest: Folder) => Crumb['drop'],
): Crumb[] {
  if (folder.source !== 'owned') {
    return [{ label: t('nav.shared'), to: '/shared' }, { label: folder.name ?? t('drive.encrypted') }]
  }
  const trail: Crumb[] = []
  let at: Folder | undefined = folder
  while (at && !at.isRoot) {
    trail.unshift({ label: at.name ?? t('drive.encrypted'), to: folderPath(at), drop: dropOn(at) })
    at = at.parentId ? index.byId.get(at.parentId) : undefined
  }
  trail.unshift({ label: t('nav.myFiles'), to: '/', drop: dropOn(index.root) })
  // The last crumb is where you are: not a link.
  const last = trail[trail.length - 1]
  if (last) delete last.to
  return trail
}

/**
 * A folder, as one list: its subfolders and files together, ordered by the
 * toolbar (newest modified first unless changed). At the top level, folders
 * outside My Files (restored from trash, made from the command line) sit
 * alongside so nothing is out of reach.
 */
export function FolderPage() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const session = useRequiredSession()
  const params = useParams()
  const folders = useFolders()
  const folder = folders.data ? resolveFolder(folders.data, params.id, params.shareId) : undefined
  useDeclareCurrentFolder(folder)
  const files = useFolderFiles(folder)
  const [prefs, updatePrefs] = useExplorerPrefs()
  const [selection, setSelection] = useState<Set<string>>(new Set())
  const [dialog, setDialog] = useState<Dialog>(null)
  const [dragging, setDragging] = useState(false)
  // An item is being dragged: the path stays on screen as a drop target.
  const [itemDrag, setItemDrag] = useState(false)
  const [looking, setLooking] = useState<QuickLookTarget | null>(null)
  const { uploadFiles, uploadDirectory } = useUploadActions()
  const renameFolder = useRenameFolder()
  const renameFile = useRenameFile()
  const trashFolder = useTrashFolder()
  const trashFile = useTrashFile()
  const publicLink = useCreatePublicLink()
  const copy = useCopy()
  const move = useMove()
  const create = useCreateActions(folder ?? null)

  const children = useMemo(() => {
    if (!folders.data || !folder) return []
    const direct = folders.data.childrenOf(folder.id)
    return folder.isRoot ? [...direct, ...folders.data.looseTopLevel] : direct
  }, [folders.data, folder])

  const { items, lookup } = useMemo(() => {
    const lookup = new Map<string, Target>()
    const list: ExplorerItem[] = []
    if (!folder) return { items: list, lookup }
    for (const child of children) {
      const item: ExplorerItem = {
        type: 'folder',
        id: child.id,
        name: child.name ?? t('drive.encrypted'),
        kind: 'folder',
        size: null,
        modifiedAt: child.updatedAt,
        color: folderHex(child.color),
      }
      list.push(item)
      lookup.set(itemKey(item), { folder: child })
    }
    for (const file of files.data ?? []) {
      const item: ExplorerItem = {
        type: 'file',
        id: file.id,
        name: file.name ?? t('drive.encrypted'),
        kind: file.kind,
        size: file.name ? file.size : null,
        modifiedAt: file.updatedAt,
      }
      list.push(item)
      lookup.set(itemKey(item), { folder, file })
    }
    return { items: list, lookup }
  }, [children, files.data, folder, t])

  const shown = useMemo(
    () => sortItems(filterItems(items, prefs.kinds), prefs.sort, i18n.language),
    [items, prefs.kinds, prefs.sort, i18n.language],
  )

  const mayChangeFile = useCallback(
    (container: Folder, file: DriveFile) =>
      container.canManage || (container.canDelete && file.uploaderUserId === session.userId),
    [session.userId],
  )

  const open = useCallback(
    (item: ExplorerItem) => {
      const target = lookup.get(itemKey(item))
      if (!target) return
      if (!target.file) {
        if (target.folder.key) void navigate(folderPath(target.folder))
        return
      }
      if (!target.file.fileKey) return
      if (target.folder.source === 'remote') {
        // Files on another server are downloaded rather than opened in place.
        void downloadFile(target.folder, target.file).catch(() => {})
        return
      }
      void navigate(filePath(target.folder, target.file.id))
    },
    [lookup, navigate],
  )

  const moveToTrash = useCallback(
    async (targets: Target[]) => {
      let moved = 0
      const undoable: string[] = []
      for (const target of targets) {
        try {
          if (target.file) {
            await trashFile.mutateAsync({ folder: target.folder, file: target.file })
            // Only an owner's items land in their own trash, where undo can reach them.
            if (target.folder.canManage) undoable.push(target.file.id)
          } else {
            await trashFolder.mutateAsync(target.folder)
            undoable.push(target.folder.id)
          }
          moved += 1
        } catch (error) {
          toast.error(apiErrorMessage(error, t('drive.trashFailed')))
        }
      }
      setSelection(new Set())
      if (moved === 0) return
      toast.success(t('drive.movedToTrash', { count: moved }), {
        action:
          undoable.length === moved
            ? {
                label: t('drive.undo'),
                onClick: () => {
                  void Promise.all(undoable.map((id) => api.post(`/trash/${id}/restore`)))
                    .then(() => folders.refetch())
                    .then(() => files.refetch())
                    .catch(() => toast.error(t('drive.undoFailed')))
                },
              }
            : undefined,
      })
    },
    [trashFile, trashFolder, t, folders, files],
  )

  /** One file as itself; a folder, or several items, as a ZIP. */
  const download = useCallback(
    async (targets: Target[]) => {
      const [only] = targets
      if (!only) return
      try {
        if (targets.length === 1 && only.file) {
          await downloadFile(only.folder, only.file)
        } else {
          const id = toast.loading(t('drive.zipping'))
          const progress = (done: number, total: number) => toast.loading(t('drive.zipProgress', { done, total }), { id })
          const archive = folder?.isRoot ? t('nav.myFiles') : (folder?.name ?? 'Kutup')
          const result = await (targets.length === 1
            ? downloadFolderZip(only.folder, progress)
            : downloadSelectionZip(targets, archive, progress)
          ).finally(() => toast.dismiss(id))
          if (result === 'empty') toast.info(t('drive.zipEmpty'))
        }
      } catch (error) {
        if (error instanceof DOMException && error.name === 'AbortError') return
        toast.error(error instanceof FsaRequiredError ? t('drive.zipTooLarge') : t('drive.downloadFailed'))
      }
    },
    [t, folder],
  )

  const actionsFor = useCallback(
    (item: ExplorerItem): ExplorerAction[] => {
      const target = lookup.get(itemKey(item))
      if (!target) return []
      const actions: ExplorerAction[] = []
      if (target.file) {
        const { file, folder: container } = target
        if (!file.fileKey) {
          return mayChangeFile(container, file)
            ? [{ id: 'trash', label: t('drive.actions.trash'), icon: <Trash2 />, onSelect: () => void moveToTrash([target]), destructive: true }]
            : []
        }
        if (container.source !== 'remote') {
          actions.push({ id: 'open', label: t('drive.actions.open'), icon: <ExternalLink />, onSelect: () => open(item) })
        }
        actions.push({ id: 'preview', label: t('drive.actions.quickLook'), icon: <Eye />, onSelect: () => setLooking({ folder: container, file }) })
        actions.push({ id: 'download', label: t('drive.actions.download'), icon: <Download />, onSelect: () => void download([target]) })
        actions.push({ id: 'copy', label: t('drive.actions.copyTo'), icon: <Copy />, onSelect: () => setDialog({ kind: 'copy', targets: [target] }) })
        if (mayMove(target)) {
          actions.push({ id: 'move', label: t('drive.actions.moveTo'), icon: <FolderInput />, onSelect: () => setDialog({ kind: 'move', targets: [target] }) })
        }
        if (mayChangeFile(container, file) && container.source !== 'remote') {
          actions.push({ id: 'rename', label: t('drive.actions.rename'), icon: <Pencil />, onSelect: () => setDialog({ kind: 'rename', target }), separated: true })
        }
        if (mayChangeFile(container, file)) {
          actions.push({ id: 'trash', label: t('drive.actions.trash'), icon: <Trash2 />, onSelect: () => void moveToTrash([target]), destructive: true, separated: !actions.some((a) => a.id === 'rename') })
        }
        return actions
      }
      const f = target.folder
      if (!f.key) return f.canManage ? [{ id: 'trash', label: t('drive.actions.trash'), icon: <Trash2 />, onSelect: () => void moveToTrash([target]), destructive: true }] : []
      actions.push({ id: 'open', label: t('drive.actions.open'), icon: <ExternalLink />, onSelect: () => open(item) })
      actions.push({ id: 'download', label: t('drive.actions.downloadZip'), icon: <Download />, onSelect: () => void download([target]) })
      actions.push({ id: 'copy', label: t('drive.actions.copyTo'), icon: <Copy />, onSelect: () => setDialog({ kind: 'copy', targets: [target] }) })
      if (mayMove(target)) {
        actions.push({ id: 'move', label: t('drive.actions.moveTo'), icon: <FolderInput />, onSelect: () => setDialog({ kind: 'move', targets: [target] }) })
      }
      if (f.canManage) {
        actions.push(
          { id: 'share', label: t('drive.actions.share'), icon: <UserPlus />, onSelect: () => setDialog({ kind: 'share', folder: f }), separated: true },
          {
            id: 'link',
            label: t('drive.actions.publicLink'),
            icon: <Link2 />,
            onSelect: () =>
              publicLink.mutate(f, {
                onSuccess: (url) => setDialog({ kind: 'link', url }),
                onError: (error) => toast.error(apiErrorMessage(error, t('drive.linkFailed'))),
              }),
          },
          { id: 'rename', label: t('drive.actions.rename'), icon: <Pencil />, onSelect: () => setDialog({ kind: 'rename', target }), separated: true },
          { id: 'color', label: t('drive.actions.color'), icon: <Palette />, onSelect: () => setDialog({ kind: 'color', folder: f }) },
          { id: 'trash', label: t('drive.actions.trash'), icon: <Trash2 />, onSelect: () => void moveToTrash([target]), destructive: true, separated: true },
        )
      }
      return actions
    },
    [lookup, mayChangeFile, moveToTrash, open, download, publicLink, t],
  )

  const selectedTargets = [...selection].flatMap((key) => {
    const target = lookup.get(key)
    return target ? [target] : []
  })
  const selectedTrashable = selectedTargets.filter((s) => (s.file ? mayChangeFile(s.folder, s.file) : s.folder.canManage))

  /** What can be done to several items at once. */
  const selectionActions = (targets: Target[]): ExplorerAction[] => {
    const readable = targets.filter((s) => (s.file ? s.file.fileKey : s.folder.key))
    const trashable = targets.filter((s) => (s.file ? mayChangeFile(s.folder, s.file) : s.folder.canManage))
    const actions: ExplorerAction[] = []
    if (readable.length === targets.length) {
      actions.push(
        { id: 'download', label: t('drive.actions.downloadZip'), icon: <Download />, onSelect: () => void download(targets) },
        { id: 'copy', label: t('drive.actions.copyTo'), icon: <Copy />, onSelect: () => setDialog({ kind: 'copy', targets }) },
      )
    }
    if (targets.every(mayMove)) {
      actions.push({ id: 'move', label: t('drive.actions.moveTo'), icon: <FolderInput />, onSelect: () => setDialog({ kind: 'move', targets }) })
    }
    if (trashable.length === targets.length) {
      actions.push({ id: 'trash', label: t('drive.actions.trash'), icon: <Trash2 />, onSelect: () => void moveToTrash(targets), destructive: true, separated: true })
    }
    return actions
  }

  const menuFor = (key: string | null): ContextMenuSpec => {
    if (key === null) {
      if (selection.size > 0) setSelection(new Set())
      const actions = [...create.actions]
      if (shown.length > 0) {
        actions.push({
          id: 'select-all',
          label: t('explorer.selectAll'),
          icon: <CheckCheck />,
          onSelect: () => setSelection(new Set(shown.map(itemKey))),
          separated: true,
        })
      }
      return { actions }
    }
    // Right-clicking outside the selection makes that item the selection.
    const keys = selection.has(key) ? selection : new Set([key])
    if (!selection.has(key)) setSelection(keys)
    if (keys.size > 1) {
      const targets = [...keys].flatMap((k) => {
        const target = lookup.get(k)
        return target ? [target] : []
      })
      return { label: t('drive.selection', { count: targets.length }), actions: selectionActions(targets) }
    }
    const item = shown.find((i) => itemKey(i) === key)
    return { actions: item ? actionsFor(item) : [] }
  }

  async function onDrop(event: DragEvent) {
    event.preventDefault()
    setDragging(false)
    if (!folder?.key || !folder.canUpload) return
    const hasDirectory = Array.from(event.dataTransfer.items).some((i) => i.webkitGetAsEntry()?.isDirectory)
    if (hasDirectory && folder.canManage) {
      const entries = await dataTransferToFolderEntries(event.dataTransfer.items)
      const byTop = new Map<string, typeof entries>()
      for (const entry of entries) {
        const top = entry.relativePath[0] ?? ''
        byTop.set(top, [...(byTop.get(top) ?? []), entry])
      }
      for (const [top, group] of byTop) {
        if (top) uploadDirectory(folder, group, top)
        else uploadFiles(folder, group.map((e) => e.file))
      }
    } else {
      uploadFiles(folder, Array.from(event.dataTransfer.files))
    }
  }

  if (folders.isPending || (folder?.key && files.isPending)) return <LoadingPanel label={t('common.loading')} />
  if (folders.isError) {
    return (
      <div className="p-6">
        <Alert variant="error">{apiErrorMessage(folders.error, t('drive.loadFailed'))}</Alert>
      </div>
    )
  }
  if (!folder || !folders.data) {
    return <EmptyState title={t('drive.folderMissingTitle')} description={t('drive.folderMissing')} />
  }

  const renaming = dialog?.kind === 'rename' ? dialog.target : null
  const copying = dialog?.kind === 'copy' ? dialog.targets : null
  const moving = dialog?.kind === 'move' ? dialog.targets : null
  // Quick Look steps through the files in the order on screen.
  const lookableFiles = shown.flatMap((item) => {
    const target = lookup.get(itemKey(item))
    return target?.file?.fileKey ? [{ folder: target.folder, file: target.file }] : []
  })
  // The selection bar: a lone item gets its own download/copy/trash, several get the bulk ones.
  const selectedItems = shown.filter((i) => selection.has(itemKey(i)))
  const barActions = (selectedItems.length === 1 && selectedItems[0] ? actionsFor(selectedItems[0]) : selectionActions(selectedTargets)).filter(
    (a) => a.id === 'download' || a.id === 'copy' || a.id === 'move' || a.id === 'trash',
  )
  const index = folders.data
  /** The items behind dragged keys, or null unless every one of them can move. */
  const draggedTargets = (keys: string[]): Target[] | null => {
    const targets = keys.flatMap((k) => {
      const target = lookup.get(k)
      return target ? [target] : []
    })
    return targets.length === keys.length && targets.every(mayMove) ? targets : null
  }
  const dropOn = (dest: Folder): Crumb['drop'] => ({
    accepts: () => {
      const keys = draggedItems()
      const targets = keys && draggedTargets(keys)
      return Boolean(targets && refusalFor(index, targets, dest) === null)
    },
    onDrop: () => {
      const keys = draggedItems()
      const targets = keys && draggedTargets(keys)
      endItemDrag()
      if (!targets) return
      setSelection(new Set())
      void move(index, targets, dest)
    },
  })
  const refusalText: Record<MoveRefusal, string> = {
    locked: t('dialogs.move.locked'),
    readOnly: t('dialogs.move.readOnly'),
    otherOwner: t('dialogs.move.otherOwner'),
    remote: t('dialogs.move.remote'),
    notOwner: t('dialogs.move.notOwner'),
    intoItself: t('dialogs.move.intoItself'),
    alreadyThere: t('dialogs.move.alreadyThere'),
  }
  const taken = new Set(items.map((i) => i.name.toLocaleLowerCase()))

  return (
    <div
      className="relative flex min-h-[calc(100svh-3.5rem)] flex-col"
      onDragOver={(e) => {
        if (!folder.canUpload || !e.dataTransfer.types.includes('Files')) return
        e.preventDefault()
        setDragging(true)
      }}
      onDragLeave={(e) => {
        if (e.currentTarget === e.target) setDragging(false)
      }}
      onDrop={(e) => void onDrop(e)}
    >
      <div className="sticky top-14 z-20 flex min-h-12 flex-wrap items-center gap-2 border-b border-border bg-background/95 px-3 py-1.5 backdrop-blur-sm md:px-6">
        {selection.size > 0 && !itemDrag ? (
          <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1" role="toolbar" aria-label={t('drive.selection', { count: selection.size })}>
            <Button variant="ghost" size="icon" aria-label={t('drive.clearSelection')} onClick={() => setSelection(new Set())}>
              <X />
            </Button>
            <span className="mr-2 text-sm font-medium">{t('drive.selection', { count: selection.size })}</span>
            {barActions.map((a) => (
                <Button key={a.id} variant="ghost" size="sm" onClick={a.onSelect}>
                  {a.icon}
                  <span className="hidden sm:inline">{a.label}</span>
                </Button>
              ))}
          </div>
        ) : (
          <Breadcrumb items={crumbsFor(folders.data, folder, t, dropOn)} className="min-w-0 flex-1" />
        )}
        <Toolbar prefs={prefs} update={updatePrefs} />
      </div>

      <ExplorerContextMenu menuFor={menuFor}>
        {files.isError ? (
          <div className="p-4">
            <Alert variant="error">{apiErrorMessage(files.error, t('drive.loadFailed'))}</Alert>
          </div>
        ) : null}
        {!folder.key ? (
          <EmptyState title={t('drive.encryptedFolderTitle')} description={t('drive.encryptedFolder')} />
        ) : shown.length === 0 ? (
          <EmptyState
            title={items.length === 0 ? t('drive.emptyTitle') : t('drive.noMatchTitle')}
            description={
              items.length === 0
                ? folder.canUpload
                  ? t('drive.emptyDescription')
                  : t('drive.emptyReadOnly')
                : t('drive.noMatchDescription')
            }
          />
        ) : (
          <Explorer
            items={shown}
            view={prefs.view}
            sort={prefs.sort}
            onSortField={(field) =>
              updatePrefs(
                field === prefs.sort.field
                  ? { dir: prefs.sort.dir === 'asc' ? 'desc' : 'asc' }
                  : { field, dir: field === 'name' || field === 'type' ? 'asc' : 'desc' },
              )
            }
            selection={selection}
            onSelectionChange={setSelection}
            onOpen={open}
            onQuickLook={(item) => {
              const target = lookup.get(itemKey(item))
              if (target?.file?.fileKey) setLooking({ folder: target.folder, file: target.file })
            }}
            actionsFor={actionsFor}
            renderPreview={
              prefs.showPreviews
                ? (item) => {
                    const target = lookup.get(itemKey(item))
                    return target?.file ? <FileThumbnail folder={target.folder} file={target.file} /> : null
                  }
                : undefined
            }
            onDeleteKey={() => selectedTrashable.length === selectedTargets.length && void moveToTrash(selectedTargets)}
            canDrag={(item) => {
              const target = lookup.get(itemKey(item))
              return Boolean(target && mayMove(target))
            }}
            canDrop={(keys, item) => {
              const dest = lookup.get(itemKey(item))
              const targets = draggedTargets(keys)
              return Boolean(dest && !dest.file && targets && refusalFor(index, targets, dest.folder) === null)
            }}
            onItemDrag={setItemDrag}
            onDropItems={(keys, item) => {
              const dest = lookup.get(itemKey(item))
              const targets = draggedTargets(keys)
              if (!dest || dest.file || !targets) return
              setSelection(new Set())
              void move(index, targets, dest.folder)
            }}
          />
        )}
      </ExplorerContextMenu>

      {dragging ? (
        <div
          className={cn(
            'pointer-events-none absolute inset-2 z-30 flex items-center justify-center rounded-lg',
            'border-2 border-dashed border-primary bg-primary/5 text-sm font-medium text-primary',
          )}
        >
          {t('drive.dropHere', { name: folder.isRoot ? t('nav.myFiles') : folder.name })}
        </div>
      ) : null}

      <NameDialog
        open={renaming !== null}
        title={t('dialogs.rename.title')}
        initial={renaming ? (renaming.file?.name ?? renaming.folder.name ?? '') : ''}
        submit={t('dialogs.rename.submit')}
        taken={taken}
        pending={renameFolder.isPending || renameFile.isPending}
        error={renameFolder.error ?? renameFile.error}
        onClose={() => {
          setDialog(null)
          renameFolder.reset()
          renameFile.reset()
        }}
        onSubmit={(name) => {
          if (!renaming) return
          const done = { onSuccess: () => setDialog(null) }
          if (renaming.file) renameFile.mutate({ folder: renaming.folder, file: renaming.file, name }, done)
          else renameFolder.mutate({ folder: renaming.folder, name }, done)
        }}
      />
      {create.elements}
      <QuickLook
        target={looking}
        onClose={() => setLooking(null)}
        onStep={
          lookableFiles.length > 1
            ? (direction) => {
                if (!looking) return
                const at = lookableFiles.findIndex((f) => f.file.id === looking.file.id)
                const next = lookableFiles[(at + direction + lookableFiles.length) % lookableFiles.length]
                if (next) {
                  setLooking(next)
                  setSelection(new Set([itemKey({ type: 'file', id: next.file.id })]))
                }
              }
            : undefined
        }
        onOpen={(target) => {
          setLooking(null)
          void navigate(filePath(target.folder, target.file.id))
        }}
        onDownload={(target) => void download([target])}
      />
      <FolderPickerDialog
        open={copying !== null}
        title={t('dialogs.copy.title', { count: copying?.length ?? 0 })}
        submit={t('dialogs.copy.submit')}
        index={index}
        start={folder}
        refusal={(dest) => {
          if (!dest.key) return t('dialogs.copy.locked')
          if (!dest.canUpload) return t('dialogs.copy.readOnly')
          const folderTargets = (copying ?? []).filter((c) => !c.file)
          if (folderTargets.length > 0 && !dest.canManage) return t('dialogs.copy.foldersOwnedOnly')
          if (folderTargets.some((c) => isWithin(index, dest, c.folder))) return t('dialogs.copy.intoItself')
          return null
        }}
        onClose={() => setDialog(null)}
        onPick={(dest) => {
          const targets = copying ?? []
          setDialog(null)
          setSelection(new Set())
          copy(index, targets, dest).catch(() => toast.error(t('dialogs.copy.failed')))
        }}
      />
      <FolderPickerDialog
        open={moving !== null}
        title={t('dialogs.move.title', { count: moving?.length ?? 0 })}
        description={t('dialogs.move.description')}
        submit={t('dialogs.move.submit')}
        index={index}
        start={folder}
        refusal={(dest) => {
          const reason = refusalFor(index, moving ?? [], dest)
          return reason ? refusalText[reason] : null
        }}
        onClose={() => setDialog(null)}
        onPick={(dest) => {
          const targets = moving ?? []
          setDialog(null)
          setSelection(new Set())
          void move(index, targets, dest)
        }}
      />
      <ColorDialog folder={dialog?.kind === 'color' ? dialog.folder : null} onClose={() => setDialog(null)} />
      <ShareDialog
        folder={dialog?.kind === 'share' ? dialog.folder : null}
        onClose={() => setDialog(null)}
        onInvite={(url, account) => setDialog({ kind: 'invite', url, account })}
      />
      <LinkDialog
        link={dialog?.kind === 'link' ? dialog.url : null}
        title={t('dialogs.publicLink.title')}
        description={t('dialogs.publicLink.description')}
        warning={t('dialogs.publicLink.warning')}
        onClose={() => setDialog(null)}
      />
      <LinkDialog
        link={dialog?.kind === 'invite' ? dialog.url : null}
        title={t('dialogs.invite.title')}
        description={t('dialogs.invite.description', { account: dialog?.kind === 'invite' ? dialog.account : '' })}
        warning={t('dialogs.invite.warning')}
        onClose={() => setDialog(null)}
      />
    </div>
  )
}
