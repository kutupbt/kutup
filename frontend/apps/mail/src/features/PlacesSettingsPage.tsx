import { ArrowDownAZ, Folder, FolderPlus, GripVertical, Pencil, Tag, Trash2 } from 'lucide-react'
import { useState, type DragEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import {
  flattenFolders,
  heightOf,
  MAX_FOLDER_DEPTH,
  reorder,
  usePlaces,
  useUpdateFolder,
  useUpdateLabel,
  type MailFolder,
  type MailLabel,
  type MailPlaces,
} from '@kutup/mail-core/places'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { openPlacesDialog } from './placesState'

type Zone = 'before' | 'inside' | 'after'

const DRAG_TYPE = 'application/x-kutup-mail-place'

function IconButton({ label, onClick, children }: { label: string; onClick: () => void; children: ReactNode }) {
  return (
    <Tooltip label={label}>
      <Button variant="ghost" size="icon" className="size-8" aria-label={label} onClick={onClick}>
        {children}
      </Button>
    </Tooltip>
  )
}

/** Where a folder dragged onto `target` would land, if it may (three deep, never inside itself). */
function allowed(places: MailPlaces, dragged: MailFolder, target: MailFolder, zone: Zone): boolean {
  if (flattenFolders([dragged]).some((f) => f.id === target.id)) return false
  const depth = zone === 'inside' ? target.depth : target.depth - 1
  return depth + heightOf(dragged) <= MAX_FOLDER_DEPTH && (zone !== 'inside' || places.folders.has(target.id))
}

/**
 * Settings → Folders and labels (Proton's `FoldersSection`, `LabelsSection`):
 * drag a folder onto another to put it inside, above or below one to
 * reorder; drag labels to reorder; sort A–Z; edit and delete.
 */
export function PlacesSettingsPage() {
  const { t } = useTranslation()
  const places = usePlaces()
  const updateFolder = useUpdateFolder()
  const updateLabel = useUpdateLabel()
  const [dragging, setDragging] = useState<{ kind: 'folder' | 'label'; id: string } | null>(null)
  const [hover, setHover] = useState<{ id: string; zone: Zone } | null>(null)
  const [sorting, setSorting] = useState<'folders' | 'labels' | null>(null)
  const [busy, setBusy] = useState(false)

  if (places.isPending) return <LoadingPanel label={t('common.loading')} />
  if (places.isError || !places.data) {
    return (
      <div className="p-6">
        <Alert variant="error">{apiErrorMessage(places.error, t('common.tryAgain'))}</Alert>
      </div>
    )
  }
  const data = places.data

  async function run(steps: (() => Promise<unknown>)[]) {
    setBusy(true)
    try {
      for (const step of steps) await step()
    } catch (error) {
      toast.error(apiErrorMessage(error, t('common.tryAgain')))
    } finally {
      setBusy(false)
    }
  }

  function dropFolder(target: MailFolder, zone: Zone) {
    const dragged = dragging?.kind === 'folder' ? data.folders.get(dragging.id) : undefined
    if (!dragged || dragged.id === target.id || !allowed(data, dragged, target, zone)) return
    if (zone === 'inside') {
      void run([() => updateFolder.mutateAsync({ id: dragged.id, parentId: target.id, position: target.children.length })])
      return
    }
    const parentId = target.parentId
    const siblings = parentId ? (data.folders.get(parentId)?.children ?? []) : data.tree
    const withDragged = siblings.some((s) => s.id === dragged.id) ? siblings : [...siblings, dragged]
    const others = withDragged.filter((s) => s.id !== dragged.id)
    const index = others.findIndex((s) => s.id === target.id) + (zone === 'after' ? 1 : 0)
    const positions = reorder(withDragged, dragged.id, index)
    void run([
      ...(dragged.parentId !== parentId ? [() => updateFolder.mutateAsync({ id: dragged.id, parentId })] : []),
      ...positions.map(({ id, position }) => () => updateFolder.mutateAsync({ id, position })),
    ])
  }

  function dropLabel(target: MailLabel, zone: Zone) {
    if (dragging?.kind !== 'label' || dragging.id === target.id) return
    const others = data.labels.filter((l) => l.id !== dragging.id)
    const index = others.findIndex((l) => l.id === target.id) + (zone === 'after' ? 1 : 0)
    void run(reorder(data.labels, dragging.id, index).map(({ id, position }) => () => updateLabel.mutateAsync({ id, position })))
  }

  function sort(which: 'folders' | 'labels') {
    const byName = <T extends { name: string }>(list: T[]) => [...list].sort((a, b) => a.name.localeCompare(b.name))
    const steps: (() => Promise<unknown>)[] = []
    if (which === 'labels') {
      byName(data.labels).forEach((l, position) => {
        if (l.position !== position) steps.push(() => updateLabel.mutateAsync({ id: l.id, position }))
      })
    } else {
      const walk = (list: MailFolder[]) =>
        byName(list).forEach((f, position) => {
          if (f.position !== position) steps.push(() => updateFolder.mutateAsync({ id: f.id, position }))
          walk(f.children)
        })
      walk(data.tree)
    }
    void run(steps).then(() => toast.success(t(which === 'folders' ? 'places.foldersSorted' : 'places.labelsSorted')))
  }

  const zoneOf = (e: DragEvent<HTMLElement>, nest: boolean): Zone => {
    const box = e.currentTarget.getBoundingClientRect()
    const at = (e.clientY - box.top) / box.height
    if (!nest) return at < 0.5 ? 'before' : 'after'
    return at < 0.25 ? 'before' : at > 0.75 ? 'after' : 'inside'
  }

  function row(
    kind: 'folder' | 'label',
    item: MailFolder | MailLabel,
    depth: number,
    actions: ReactNode,
  ) {
    const zone = hover?.id === item.id ? hover.zone : null
    const folder = kind === 'folder' ? (item as MailFolder) : null
    const draggedFolder = dragging?.kind === 'folder' ? data.folders.get(dragging.id) : undefined
    const ok = (z: Zone) => (folder ? !!draggedFolder && allowed(data, draggedFolder, folder, z) : dragging?.kind === 'label')
    return (
      <li
        key={item.id}
        draggable={!busy}
        onDragStart={(e) => {
          e.dataTransfer.setData(DRAG_TYPE, item.id)
          e.dataTransfer.effectAllowed = 'move'
          setDragging({ kind, id: item.id })
        }}
        onDragEnd={() => {
          setDragging(null)
          setHover(null)
        }}
        onDragOver={(e) => {
          if (!dragging || dragging.kind !== kind || dragging.id === item.id) return
          const z = zoneOf(e, kind === 'folder')
          if (!ok(z)) return
          e.preventDefault()
          setHover({ id: item.id, zone: z })
        }}
        onDragLeave={() => setHover((now) => (now?.id === item.id ? null : now))}
        onDrop={(e) => {
          e.preventDefault()
          const z = zoneOf(e, kind === 'folder')
          setHover(null)
          if (folder) dropFolder(folder, z)
          else dropLabel(item, z)
        }}
        className={cn(
          'flex items-center gap-2 border-b border-border px-3 py-2 last:border-b-0',
          zone === 'inside' && 'bg-primary/10 ring-1 ring-primary',
          zone === 'before' && 'shadow-[inset_0_2px_0_var(--primary)]',
          zone === 'after' && 'shadow-[inset_0_-2px_0_var(--primary)]',
        )}
        style={{ paddingLeft: `${0.75 + (depth - 1) * 1.5}rem` }}
      >
        <GripVertical className="size-4 shrink-0 cursor-grab text-muted-foreground" aria-hidden />
        {kind === 'folder' ? <Folder className="size-4 shrink-0" style={{ color: item.color }} /> : <Tag className="size-4 shrink-0" style={{ color: item.color }} />}
        <span className="min-w-0 flex-1 truncate text-sm">{item.name}</span>
        {actions}
      </li>
    )
  }

  const folderRows = (list: MailFolder[]): ReactNode[] =>
    list.flatMap((f) => [
      row(
        'folder',
        f,
        f.depth,
        <>
          {f.depth < MAX_FOLDER_DEPTH ? (
            <IconButton label={t('places.newSubfolder')} onClick={() => openPlacesDialog({ kind: 'edit', target: { kind: 'folder', parentId: f.id } })}>
              <FolderPlus />
            </IconButton>
          ) : null}
          <IconButton label={t('places.editFolder')} onClick={() => openPlacesDialog({ kind: 'edit', target: { kind: 'folder', folder: f } })}>
            <Pencil />
          </IconButton>
          <IconButton label={t('places.deleteFolder')} onClick={() => openPlacesDialog({ kind: 'delete', folder: f })}>
            <Trash2 />
          </IconButton>
        </>,
      ),
      ...folderRows(f.children),
    ])

  return (
    // Mail's shell is flush (the list runs edge to edge); a settings page has its own margins.
    <div className="h-full overflow-y-auto px-4 py-6 md:px-8">
    <PageBody>
      <PageHeader title={t('places.settingsTitle')} description={t('places.settingsDescription')} />
      {data.unreadable ? <Alert variant="warn">{t('places.unreadable', { count: data.unreadable })}</Alert> : null}
      <section className="space-y-3" aria-labelledby="folders-heading">
        <div className="flex flex-wrap items-center gap-2">
          <h2 id="folders-heading" className="flex-1 font-display text-lg font-semibold">
            {t('places.folders')}
          </h2>
          <Button variant="outline" size="sm" disabled={busy || data.tree.length < 2} onClick={() => setSorting('folders')}>
            <ArrowDownAZ />
            {t('places.sort')}
          </Button>
          <Button size="sm" onClick={() => openPlacesDialog({ kind: 'edit', target: { kind: 'folder' } })}>
            <FolderPlus />
            {t('places.newFolder')}
          </Button>
        </div>
        <p className="text-sm text-muted-foreground">{t('places.foldersHint')}</p>
        {data.tree.length ? (
          <ul className="rounded-lg border border-border">{folderRows(data.tree)}</ul>
        ) : (
          <EmptyState title={t('places.noFolders')} description={t('places.noFoldersHint')} />
        )}
      </section>
      <section className="mt-8 space-y-3" aria-labelledby="labels-heading">
        <div className="flex flex-wrap items-center gap-2">
          <h2 id="labels-heading" className="flex-1 font-display text-lg font-semibold">
            {t('places.labels')}
          </h2>
          <Button variant="outline" size="sm" disabled={busy || data.labels.length < 2} onClick={() => setSorting('labels')}>
            <ArrowDownAZ />
            {t('places.sort')}
          </Button>
          <Button size="sm" onClick={() => openPlacesDialog({ kind: 'edit', target: { kind: 'label' } })}>
            <Tag />
            {t('places.newLabel')}
          </Button>
        </div>
        <p className="text-sm text-muted-foreground">{t('places.labelsHint')}</p>
        {data.labels.length ? (
          <ul className="rounded-lg border border-border">
            {data.labels.map((l) =>
              row(
                'label',
                l,
                1,
                <>
                  <IconButton label={t('places.editLabel')} onClick={() => openPlacesDialog({ kind: 'edit', target: { kind: 'label', label: l } })}>
                    <Pencil />
                  </IconButton>
                  <IconButton label={t('places.deleteLabel')} onClick={() => openPlacesDialog({ kind: 'delete', label: l })}>
                    <Trash2 />
                  </IconButton>
                </>,
              ),
            )}
          </ul>
        ) : (
          <EmptyState title={t('places.noLabels')} description={t('places.noLabelsHint')} />
        )}
      </section>
      <Dialog open={sorting !== null} onOpenChange={(open) => !open && setSorting(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('places.sortTitle')}</DialogTitle>
            <DialogDescription>{t(sorting === 'labels' ? 'places.sortLabelsDescription' : 'places.sortFoldersDescription')}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSorting(null)}>
              {t('common.cancel')}
            </Button>
            <Button
              onClick={() => {
                const which = sorting
                setSorting(null)
                if (which) sort(which)
              }}
            >
              {t('places.sort')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </PageBody>
    </div>
  )
}
