import { ArchiveRestore, FolderInput, Trash2, X } from 'lucide-react'
import { useEffect, useMemo, useState, type DragEvent, type KeyboardEvent, type MouseEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { cn } from '@kutup/ui/lib/cn'
import { emptySelection, inOrder, keepShown, selectAll, selectRange, toggle, type Selection } from '../lib/selection'
import type { VaultSession } from '../sync/vaultSession'
import { fieldValue, type EntryView, type GroupView, type VaultView } from '../vault/types'
import { DRAG_TYPE } from './entryDrop'
import { SiteIcon } from './SiteIcon'

/**
 * A vault's entry list, with several entries selected at once
 * (docs/plans/pass-parity.md, "Bulk actions and the entry list"): a checkbox
 * or Ctrl/Cmd-click toggles one, Shift-click takes a range, Ctrl+A takes all
 * shown, Esc clears. What is selected moves to a group, goes to the recycle
 * bin, comes back from it, or is deleted for good from it, each as one edit;
 * on a desktop, rows drag onto the groups (never deleting for good). A plain
 * click opens the entry. A read-only vault has none of it.
 */
export function EntryList({
  session,
  view,
  shown,
  currentId,
  viewingBin,
  pictures,
  onOpen,
}: {
  session: VaultSession
  view: VaultView
  shown: EntryView[]
  currentId: string | undefined
  viewingBin: boolean
  pictures: Map<string, string>
  onOpen: (id: string) => void
}) {
  const { t } = useTranslation()
  const editable = session.canEdit
  const order = useMemo(() => shown.map((e) => e.id), [shown])
  const [selection, setSelection] = useState<Selection>(emptySelection)
  const [confirming, setConfirming] = useState<'recycle' | 'forGood' | null>(null)
  const selected = inOrder(selection, order)
  const forGood = viewingBin || !view.recycleBinEnabled
  const targets = view.groups.filter((g) => !g.inRecycleBin)

  // Entries leave the list (moved, deleted, another device's save): so do
  // they leave the selection.
  useEffect(() => setSelection((current) => keepShown(current, order)), [order])

  const run = async (op: Parameters<VaultSession['apply']>[0], done: string) => {
    try {
      await session.apply(op)
      setSelection(emptySelection)
      toast.success(done)
    } catch {
      toast.error(t('entry.saveFailed'))
    }
  }
  const moveTo = (group: GroupView) =>
    void run({ op: 'moveEntries', ids: selected, groupId: group.id }, t('bulk.moved', { count: selected.length, group: group.name }))
  const restore = () => void run({ op: 'restoreEntries', ids: selected }, t('bulk.restored', { count: selected.length }))
  const remove = () => {
    const count = selected.length
    setConfirming(null)
    void run({ op: 'deleteEntries', ids: selected }, t(forGood ? 'bulk.deletedForGood' : 'bulk.recycled', { count }))
  }

  const click = (event: MouseEvent, id: string) => {
    if (editable && event.shiftKey) {
      event.preventDefault()
      setSelection((current) => selectRange(current, order, id))
    } else if (editable && (event.ctrlKey || event.metaKey)) {
      event.preventDefault()
      setSelection((current) => toggle(current, id))
    } else {
      onOpen(id)
    }
  }
  const keys = (event: KeyboardEvent) => {
    if (!editable) return
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'a') {
      event.preventDefault()
      setSelection(selectAll(order))
    } else if (event.key === 'Escape' && selection.ids.size > 0) {
      event.preventDefault()
      setSelection(emptySelection)
    }
  }
  const dragStart = (event: DragEvent, id: string) => {
    const ids = selection.ids.has(id) ? selected : [id]
    event.dataTransfer.setData(DRAG_TYPE, JSON.stringify(ids))
    event.dataTransfer.effectAllowed = 'move'
  }

  return (
    <>
      {editable && selected.length > 0 ? (
        <div role="toolbar" aria-label={t('bulk.toolbar')} className="flex flex-wrap items-center gap-1 border-b border-border bg-accent/40 px-2 py-1.5" data-testid="entry-selection">
          <span className="mr-auto px-1 text-sm font-medium">{t('bulk.selected', { count: selected.length })}</span>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm">
                <FolderInput />
                {t('bulk.moveTo')}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="max-h-80 overflow-y-auto">
              {targets.map((g) => (
                <DropdownMenuItem key={g.id} onSelect={() => moveTo(g)}>
                  <span style={{ paddingInlineStart: `${g.depth * 0.75}rem` }}>{g.name}</span>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
          {viewingBin ? (
            <Button variant="ghost" size="sm" onClick={restore}>
              <ArchiveRestore />
              {t('bulk.restore')}
            </Button>
          ) : null}
          <Button variant="ghost" size="sm" onClick={() => setConfirming(forGood ? 'forGood' : 'recycle')}>
            <Trash2 />
            {forGood ? t('bulk.deleteForGood') : t('bulk.recycle')}
          </Button>
          <Button variant="ghost" size="icon" className="size-8" aria-label={t('bulk.clear')} onClick={() => setSelection(emptySelection)}>
            <X />
          </Button>
        </div>
      ) : null}
      <ul className="flex-1 overflow-y-auto outline-none" aria-label={t('entries.label')} aria-multiselectable={editable || undefined} tabIndex={-1} onKeyDown={keys}>
        {shown.map((e) => {
          const checked = selection.ids.has(e.id)
          const title = fieldValue(e, 'Title') || t('entry.untitled')
          return (
            <li
              key={e.id}
              className={cn('group/entry flex items-center border-b border-border', checked && 'bg-accent/40')}
              draggable={editable}
              onDragStart={editable ? (event) => dragStart(event, e.id) : undefined}
              onKeyDown={keys}
            >
              {editable ? (
                <span className="flex pl-3">
                  <Checkbox
                    checked={checked}
                    onClick={(event) => {
                      // Shift: the range, not a toggle (Radix skips its own on a prevented click).
                      if (!event.shiftKey) return
                      event.preventDefault()
                      setSelection((current) => selectRange(current, order, e.id))
                    }}
                    onCheckedChange={() => setSelection((current) => toggle(current, e.id))}
                    aria-label={t('bulk.select', { title })}
                    className={cn(selected.length === 0 && 'opacity-0 group-hover/entry:opacity-100 focus-visible:opacity-100')}
                  />
                </span>
              ) : null}
              <button
                type="button"
                onClick={(event) => click(event, e.id)}
                aria-current={e.id === currentId ? 'true' : undefined}
                className={cn('flex min-w-0 flex-1 items-center gap-3 px-3 py-2.5 text-left hover:bg-accent/50', e.id === currentId && 'bg-accent')}
              >
                <SiteIcon title={fieldValue(e, 'Title')} address={fieldValue(e, 'URL')} picture={e.customIcon ? pictures.get(e.customIcon) : null} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium">{title}</span>
                  <span className="block truncate text-xs text-muted-foreground">{fieldValue(e, 'UserName') || fieldValue(e, 'URL')}</span>
                </span>
                {e.review.length > 0 ? <Badge variant="warn">{t('review.badge')}</Badge> : null}
              </button>
            </li>
          )
        })}
      </ul>
      <ConfirmDestructive
        open={confirming !== null}
        onOpenChange={(open) => !open && setConfirming(null)}
        title={confirming === 'forGood' ? t('bulk.deleteForGoodTitle', { count: selected.length }) : t('bulk.recycleTitle', { count: selected.length })}
        description={confirming === 'forGood' ? t('bulk.deleteForGoodDescription', { count: selected.length }) : t('bulk.recycleDescription', { count: selected.length })}
        warning={confirming === 'forGood' ? t('bulk.cannotUndo') : undefined}
        submit={confirming === 'forGood' ? t('bulk.deleteForGood') : t('bulk.recycle')}
        errorFallback={t('entry.saveFailed')}
        onConfirm={remove}
      />
    </>
  )
}
