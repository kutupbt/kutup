import { Archive, Check, Folder, FolderInput, Inbox, Minus, OctagonAlert, Plus, Search, Tag, Trash2 } from 'lucide-react'
import { useMemo, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { FolderId, MailMessage } from '@kutup/mail-core/api'
import { useCreateFilter, useDeleteFilter, type FilterActions } from '@kutup/mail-core/filters'
import { flattenFolders, usePlaces } from '@kutup/mail-core/places'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'
import { Popover, PopoverContent, PopoverTrigger } from '@kutup/ui/components/popover'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { movesFor, useMailActions, type MoveTarget } from './mailActions'
import { openPlacesDialog } from './placesState'

export type PickerMode = 'move' | 'label'

const MOVE_ICON: Record<MoveTarget, ReactNode> = {
  inbox: <Inbox />,
  archive: <Archive />,
  spam: <OctagonAlert />,
  trash: <Trash2 />,
}

function Row({ children, onClick, active }: { children: ReactNode; onClick: () => void; active?: boolean }) {
  return (
    <li>
      <button
        type="button"
        onClick={onClick}
        className={cn(
          'flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-muted focus-visible:bg-muted focus-visible:outline-none [&_svg]:size-4 [&_svg]:shrink-0',
          active && 'bg-muted',
        )}
      >
        {children}
      </button>
    </li>
  )
}

/**
 * Proton's "Move to" and "Label as" (`MoveDropdown`, `LabelDropdown`): a
 * searchable list of places, "Create folder "…"" from the search, and for
 * labels a checkbox per label (all, some or none of the messages have it),
 * "Also archive" and Apply.
 */
function PickerBody({ mode, rows, folder, onDone }: { mode: PickerMode; rows: MailMessage[]; folder: FolderId; onDone: (archived?: boolean) => void }) {
  const { t } = useTranslation()
  const places = usePlaces()
  const actions = useMailActions()
  const [query, setQuery] = useState('')
  const [alsoArchive, setAlsoArchive] = useState(false)
  // Proton's "Always move/label sender's emails": a filter for these senders.
  const [always, setAlways] = useState(false)
  const createFilter = useCreateFilter()
  const deleteFilter = useDeleteFilter()
  const senders = [...new Set(rows.filter((m) => m.direction === 'inbound' && m.from).map((m) => m.from!.address.toLowerCase()))]

  function rememberSenders(actions: FilterActions, place: string) {
    if (!always || senders.length === 0) return
    const who = senders.length === 1 ? senders[0] : t('filters.sendersCount', { count: senders.length })
    // The picker closes at once; mutateAsync still reports after it is gone.
    createFilter
      .mutateAsync({
        name: t(mode === 'move' ? 'filters.senderMoveName' : 'filters.senderLabelName', { who, place }),
        match: 'any',
        conditions: senders.map((address) => ({ field: 'sender', op: 'is', negate: false, value: address })),
        actions,
        source: 'sender',
      })
      .then(
        (id) =>
          toast.success(t(mode === 'move' ? 'filters.senderMoved' : 'filters.senderLabelled', { who, place }), {
            action: { label: t('moved.undo'), onClick: () => void deleteFilter.mutateAsync(id).catch(() => undefined) },
          }),
        (error: unknown) => toast.error(apiErrorMessage(error, t('common.tryAgain'))),
      )
  }
  // A label's wanted state, once changed: true (all), false (none).
  const [changed, setChanged] = useState<Map<string, boolean>>(new Map())
  const q = query.trim().toLocaleLowerCase()
  const folders = useMemo(() => (places.data ? flattenFolders(places.data.tree) : []), [places.data])
  const shownFolders = q ? folders.filter((f) => f.name.toLocaleLowerCase().includes(q)) : folders
  const labels = places.data?.labels ?? []
  const shownLabels = q ? labels.filter((l) => l.name.toLocaleLowerCase().includes(q)) : labels
  const exact = (mode === 'move' ? folders : labels).some((p) => p.name.trim().toLocaleLowerCase() === q)
  const fixed = movesFor(folder).filter((target) => !q || t(`actions.moveTo.${target}`).toLocaleLowerCase().includes(q))

  function create() {
    openPlacesDialog({
      kind: 'edit',
      target: mode === 'move' ? { kind: 'folder', name: query.trim() } : { kind: 'label', name: query.trim() },
      onCreated: (id, name) => {
        if (mode === 'move') actions.move(rows, { folder: id, name })
        else actions.mark(rows, { addLabels: [id] })
      },
    })
    onDone()
  }

  function apply() {
    const add = [...changed].filter(([, on]) => on).map(([id]) => id)
    const remove = [...changed].filter(([, on]) => !on).map(([id]) => id)
    if (add.length || remove.length) actions.mark(rows, { addLabels: add, removeLabels: remove })
    if (add.length) {
      rememberSenders({ labels: add, ...(alsoArchive ? { folder: 'archive' } : {}) }, add.map((id) => places.data?.labelsById.get(id)?.name ?? '').join(', '))
    }
    if (alsoArchive) actions.move(rows, 'archive')
    onDone(alsoArchive)
  }

  const state = (id: string): boolean | 'indeterminate' => {
    const wanted = changed.get(id)
    if (wanted !== undefined) return wanted
    const having = rows.filter((m) => m.labels.includes(id)).length
    return having === 0 ? false : having === rows.length ? true : 'indeterminate'
  }

  return (
    <div className="space-y-2">
      <div className="relative">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
        <Input
          autoFocus
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t(mode === 'move' ? 'places.filterFolders' : 'places.filterLabels')}
          aria-label={t(mode === 'move' ? 'places.filterFolders' : 'places.filterLabels')}
          className="h-8 pl-8"
          onKeyDown={(e) => {
            if (e.key === 'Enter' && q && !exact) {
              e.preventDefault()
              create()
            }
          }}
        />
      </div>
      <ul className="max-h-72 space-y-0.5 overflow-y-auto" aria-label={t(mode === 'move' ? 'places.moveTo' : 'places.labelAs')}>
        {mode === 'move' ? (
          <>
            {fixed.map((target) => (
              <Row key={target} onClick={() => {
                  actions.move(rows, target)
                  rememberSenders({ folder: target }, t(`folders.${target}`))
                  onDone(true)
                }}>
                {MOVE_ICON[target]}
                {folder === 'spam' && target === 'inbox' ? t('actions.notSpam') : t(`actions.moveTo.${target}`)}
              </Row>
            ))}
            {shownFolders.map((f) => (
              <Row key={f.id} onClick={() => {
                  actions.move(rows, { folder: f.id, name: f.name })
                  rememberSenders({ folder: `custom:${f.id}` }, f.name)
                  onDone(true)
                }}>
                <span style={{ width: `${(f.depth - 1) * 0.75}rem` }} />
                <Folder style={{ color: f.color }} />
                <span className="truncate">{f.name}</span>
              </Row>
            ))}
          </>
        ) : (
          shownLabels.map((l) => {
            const on = state(l.id)
            return (
              <Row key={l.id} onClick={() => setChanged((now) => new Map(now).set(l.id, on !== true))}>
                <span className={cn('flex size-4 items-center justify-center rounded border', on !== false ? 'border-primary bg-primary text-primary-foreground' : 'border-input')} aria-hidden>
                  {on === true ? <Check className="size-3" /> : on === 'indeterminate' ? <Minus className="size-3" /> : null}
                </span>
                <Tag style={{ color: l.color }} />
                <span className="truncate">{l.name}</span>
              </Row>
            )
          })
        )}
        {q && !exact ? (
          <Row onClick={create}>
            <Plus />
            <span className="truncate">{t(mode === 'move' ? 'places.createFolderNamed' : 'places.createLabelNamed', { name: query.trim() })}</span>
          </Row>
        ) : null}
        {!q && (mode === 'move' ? folders.length === 0 : labels.length === 0) ? (
          <li className="px-2 py-1.5 text-xs text-muted-foreground">{t(mode === 'move' ? 'places.noFolders' : 'places.noLabels')}</li>
        ) : null}
      </ul>
      {senders.length ? (
        <label className="flex items-center gap-2 border-t border-border pt-2 text-sm">
          <Checkbox checked={always} onCheckedChange={(on) => setAlways(on === true)} />
          {t(mode === 'move' ? 'filters.alwaysMove' : 'filters.alwaysLabel')}
        </label>
      ) : null}
      {mode === 'label' ? (
        <div className="flex items-center gap-2 border-t border-border pt-2">
          <label className="flex flex-1 items-center gap-2 text-sm">
            <Checkbox checked={alsoArchive} onCheckedChange={(on) => setAlsoArchive(on === true)} />
            {t('places.alsoArchive')}
          </label>
          <Button size="sm" onClick={apply}>
            {t('places.apply')}
          </Button>
        </div>
      ) : null}
    </div>
  )
}

/** The toolbar buttons: Move to and Label as, as popovers. */
export function PickerButton({ mode, rows, folder, onMoved }: { mode: PickerMode; rows: MailMessage[]; folder: FolderId; onMoved?: () => void }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const label = t(mode === 'move' ? 'places.moveTo' : 'places.labelAs')
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <Tooltip label={`${label} (${mode === 'move' ? 'M' : 'L'})`}>
        <PopoverTrigger asChild>
          <Button variant="ghost" size="icon" aria-label={label}>
            {mode === 'move' ? <FolderInput /> : <Tag />}
          </Button>
        </PopoverTrigger>
      </Tooltip>
      <PopoverContent align="end" className="w-72 p-2">
        <PickerBody
          mode={mode}
          rows={rows}
          folder={folder}
          onDone={(moved) => {
            setOpen(false)
            if (moved) onMoved?.()
          }}
        />
      </PopoverContent>
    </Popover>
  )
}

/** The same picker in a dialog, for the M and L keys. */
export function PickerDialog({
  mode,
  rows,
  folder,
  onClose,
  onMoved,
}: {
  mode: PickerMode
  rows: MailMessage[]
  folder: FolderId
  onClose: () => void
  onMoved?: () => void
}) {
  const { t } = useTranslation()
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{t(mode === 'move' ? 'places.moveTo' : 'places.labelAs')}</DialogTitle>
        </DialogHeader>
        <PickerBody
          mode={mode}
          rows={rows}
          folder={folder}
          onDone={(moved) => {
            onClose()
            if (moved) onMoved?.()
          }}
        />
      </DialogContent>
    </Dialog>
  )
}
